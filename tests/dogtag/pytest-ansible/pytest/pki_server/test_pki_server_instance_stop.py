"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI-SERVER CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki-server instance commands needs to be tested:
#   pki-server instance-stop
#   pki-server instance-stop --help
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


def test_pki_server_instance_stop_help_command(ansible_module):
    """
    :id: 42cd278d-2c98-4479-853f-047dc5d07bcd
    :Title: Test pki-server instace-stop --help command, BZ: 1339263
    :Description: test pki-server instance-stop --help command, This test also verifies bugzilla
                  id : 1339263
    :CaseComponent: \-
    :Requirement: Pki Server Instance
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server instance-stop --help command shows the following output.
    
        Usage: pki-server instance-stop [OPTIONS] <instance ID>
        -v, --verbose                Run in verbose mode.
        --help                   Show help message.
    """
    help_command = 'pki-server instance-stop --help'
    cmd_output = ansible_module.command(help_command)
    for result in cmd_output.values():
        if result['rc'] == 0:
            assert "Usage: pki-server instance-stop [OPTIONS] <instance ID>" in result['stdout']
            assert "  -v, --verbose                Run in verbose mode." in result['stdout']
            assert "      --help                   Show help message." in result['stdout']
        else:
            pytest.xfail("Failed to run pki-server instance-stop --help command")


def test_pki_server_instance_stop_command(ansible_module):
    """
    :id: 42cd278d-2c98-4479-853f-047dc5d07bcd
    :Title: Test pki-server instace-stop command
    :Description: test pki-server instance-stop command
    :CaseComponent: \-
    :Requirement: Pki Server Instance
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server instance-stop command stop the instance.
    """

    # Store subsystems in list
    subsystems = [constants.CA_INSTANCE_NAME, constants.KRA_INSTANCE_NAME,
                  constants.OCSP_INSTANCE_NAME, constants.TKS_INSTANCE_NAME,
                  constants.TPS_INSTANCE_NAME]

    for system in subsystems:

        stop_command = 'pki-server instance-stop {}'.format(system)
        start_command = 'pki-server instance-start {}'.format(system)
        # Start the instance
        stop_instance = ansible_module.command(stop_command)
        for result in stop_instance.values():
            if result['rc'] == 0:
                if " instance already stopped" in result['stdout']:
                    assert '{} instance already stopped'.format(system) in result['stdout']
                else:
                    assertstr = system + " instance stopped"
                    assert assertstr in result['stdout']
            else:
                pytest.xfail("Failed to ran pki-server instance-start " + system + " command")
        ansible_module.command(start_command)


def test_pki_server_instance_stop_command_when_instance_already_stop(ansible_module):
    """
    :id: bd751cdb-1dc6-4880-8d88-63c8f2814696
    :Title: Test pki-server instance-stop command when instance already stopped.
    :Description: test pki-server instance-stop command
    :CaseComponent: \-
    :Requirement: Pki Server Instance
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults: Verify whether pki-server instance-stop command stop the instance.
    """
    subsystems = [constants.CA_INSTANCE_NAME, constants.KRA_INSTANCE_NAME,
                  constants.OCSP_INSTANCE_NAME, constants.TKS_INSTANCE_NAME,
                  constants.TPS_INSTANCE_NAME]

    for system in subsystems:

        stop_command = 'pki-server instance-stop {}'.format(system)
        start_command = 'pki-server instance-start {}'.format(system)
        # Start the instance
        ansible_module.command(stop_command)
        stop_instance = ansible_module.command(stop_command)
        for result in stop_instance.values():
            if result['rc'] == 0:
                if " instance already stopped" in result['stdout']:
                    assert '{} instance already stopped'.format(system) in result['stdout']
                else:
                    assertstr = system + " instance stopped"
                    assert assertstr in result['stdout']
            else:
                pytest.xfail("Failed to ran pki-server instance-start " + system + " command")
        ansible_module.command(start_command)


@pytest.mark.xfail(raises=CalledProcessError)
def test_pki_server_instance_stop_command_when_instance_not_exists(ansible_module):
    """
    :id: 62faea70-344f-4b04-9460-a7ed254c24b5
    :Title: Test pki-server instace-stop command when instance does not exits, BZ:1348433
    :Description: test pki-server instance-stop command This test also verifies BZ: 1348433
    :CaseComponent: \-
    :Requirement: Pki Server Instance
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults: 
        1. Verify whether pki-server instance-stop command stop the instance when the 
           instance is does not exists.
    """
    subsystems = "ABcCA"

    instance_stop = 'pki-server instance-stop {}'.format(subsystems)

    cmd_output = ansible_module.command(instance_stop)
    for result in cmd_output.values():
        if result['rc'] >= 0:
            assert "ERROR: Invalid instance {}".format(subsystems) in result['stdout']
        else:
            pytest.xfail("Failed to run pki-server instance-stop " + subsystems + " command")
