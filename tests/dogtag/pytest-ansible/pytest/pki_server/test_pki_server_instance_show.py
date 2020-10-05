"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI-SERVER CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki-server instance commands needs to be tested:
#   pki-server instance-show --help
#   pki-server instance-show
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

import os
import sys
from subprocess import CalledProcessError

import pytest

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants
TOPOLOGY = constants.CA_INSTANCE_NAME.split("-")[-2]


def test_pki_server_instance_show_command(ansible_module):
    """
    :id: 9361795f-ef9d-49d5-a706-b0d55b362600
    :Title: Test pki-server instance-show command
    :Description: test pki-server instance-show command
    :Requirement: Pki Server Instance
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults: Verify whether pki-server instance-show command shows
        the instance is present or not.
    """
    subsystems = ['ca', 'kra']  # TODO remove after build , 'ocsp', 'tks', 'tps']

    for system in subsystems:
        if TOPOLOGY == '01':
            instance = 'pki-tomcat'
            topology_name = 'topology-01-CA'
        else:
            instance = eval("constants.{}_INSTANCE_NAME".format(system.upper()))
        ansible_module.command('pki-server instance-start {}'.format(instance))
        instance_show = 'pki-server instance-show {}'.format(instance)

        cmd_output = ansible_module.command(instance_show)
        for result in cmd_output.values():
            if result['rc'] == 0:
                assert "Instance ID: {}".format(instance) in result['stdout']
                assert "Active: True" in result['stdout']
            else:
                pytest.skip("Failed to run pki-server instance-show " + instance + " command")


def test_pki_server_instance_show_with_help_command(ansible_module):
    """
    :id: ffd9f829-00cf-4cd0-9ad7-78d20218fcf3
    :Title: Test pki-server instance-show --help command, BZ: 1339263
    :Description: test pki-server instance-show --help command.
                 This test also verifies bugzilla id : 1339263
    :Requirement: Pki Server Instance
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Setup:
    :ExpectedResults:
        1. Verify whether pki-server instance-show --help command shows
        the following commands.

        Usage: pki-server instance-show [OPTIONS] <instance ID>

          -v, --verbose                Run in verbose mode.
              --help                   Show help message.
    """

    help_command = 'pki-server instance-show --help'

    cmd_output = ansible_module.command(help_command)
    for result in cmd_output.values():
        if result['rc'] == 0:
            assert "Usage: pki-server instance-show [OPTIONS] <instance ID>" in result['stdout']
            assert "-v, --verbose                      Run in verbose mode." in result['stdout']
            assert "--debug                        Run in debug mode." in result['stdout']
            assert "--help                         Show help message." in result['stdout']
        else:
            pytest.skip("Failed to run pki-server instance-show --help command")


def test_pki_server_instance_show_when_instance_is_disabled(ansible_module):
    """
    :id: 397d050b-7fe3-4aa8-99d3-ddcbb666dbe5
    :Title: Test pki-server instance-show command when instance is disabled.
    :Description: test pki-server instance-show command
    :Requirement: Pki Server Instance
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server instance-show command shows the instance name and active
        status False when it is disabled.
    """
    subsystems = ['ca', 'kra']  # TODO remove after build , 'ocsp', 'tks', 'tps']

    for system in subsystems:
        if TOPOLOGY == '01':
            instance = 'pki-tomcat'
            topology_name = 'topology-01-CA'
        else:
            instance = eval("constants.{}_INSTANCE_NAME".format(system.upper()))
            topology_name = constants.CA_INSTANCE_NAME
        instance_stop = 'pki-server instance-stop {}'.format(instance)
        instance_start = 'pki-server instance-start {}'.format(instance)
        instance_show = 'pki-server instance-show {}'.format(instance)

        stop_instance = ansible_module.command(instance_stop)
        for result in stop_instance.values():
            if result['rc'] == 0:
                assert "stopped" in result['stdout']

        show_instance = ansible_module.command(instance_show)
        for result in show_instance.values():
            if result['rc'] == 0:
                assert 'Instance ID: {}'.format(instance) in result['stdout']
                assert 'Active: False' in result['stdout']
            else:
                pytest.skip()

        ansible_module.command(instance_start)


#@pytest.mark.xfail(raises=CalledProcessError)
def test_pki_server_instance_show_when_instance_is_not_present(ansible_module):
    """
    :id: d7dd5455-9f48-494e-b9c3-bae1bd897bda
    :Title: Test pki-server instance-show command when instance is not present, BZ: 1348433
    :Description: test pki-server instance-show command. This test also verifies
                  bugzilla id : 1348433
    :Requirement: Pki Server Instance
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults: Verify whether pki-server instance-show command shows
        the instance name and active status False when it is disabled.

    """
    system = "ABcCA"

    instance_show = 'pki-server instance-show {}'.format(system)

    cmd_show = ansible_module.command(instance_show)
    for result in cmd_show.values():
        if result['rc'] == 0:
            assert "Instance ID: " + system in result['stdout']
            assert "Active: False" in result['stdout']
            pytest.skip("Failed to ran pki-server instance-show command with invalid instance.")


def test_pki_server_instance_show_when_instance_is_enabled(ansible_module):
    """
    :id: e2b4410d-896b-420e-9331-1e3744a7c26b
    :Title: Test pki-server instance-show command when instance is enabled
    :Description: test pki-server instance-show command
    :Requirement: Pki Server Instance
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server instance-show command shows the instance name and
        active status True when it is enabled.
    """
    # Store subsystems in list
    subsystems = ['ca', 'kra']  # TODO remove after build, 'ocsp', 'tks', 'tps']

    for system in subsystems:
        # Store commands in list
        if TOPOLOGY == '01':
            instance = 'pki-tomcat'
            topology_name = 'topology-01-CA'
        else:
            instance = eval("constants.{}_INSTANCE_NAME".format(system.upper()))
            topology_name = constants.CA_INSTANCE_NAME
        instance_start = 'pki-server instance-start {}'.format(instance)
        instance_show = 'pki-server instance-show {}'.format(instance)

        cmd_output = ansible_module.command(instance_start)
        for result in cmd_output.values():
            if result['rc'] == 0:
                if 'already started' not in result['stdout']:
                    assert instance + " instance started" in result['stdout']
                else:
                    assert instance + " instance already started" in result['stdout']
        cmd_show = ansible_module.command(instance_show)
        for result in cmd_show.values():
            if result['rc'] == 0:
                assert 'Instance ID: ' + instance in result['stdout']
                assert 'Active: True' in result['stdout']
            else:
                pytest.skip("Failed to ran pki-server instance-show command when instance "
                             "is disabled.")
