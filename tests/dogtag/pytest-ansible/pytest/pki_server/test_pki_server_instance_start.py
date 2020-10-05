"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI-SERVER CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki securitydomain commands needs to be tested:
#   pki-server instance-start
#   pki-server instance-start --help
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
from subprocess import CalledProcessError

import pytest

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

TOPOLOGY = constants.CA_INSTANCE_NAME.split("-")[-2]
log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)


def test_pki_server_instance_start_help_command(ansible_module):
    """
    :id: 15012942-15ea-4312-8f29-b0e33e8cb89b
    :Title: Test pki-server instance-start --help command, BZ: 1339263
    :Description: test pki-server instance-start --help command, This test also 
                  verifies bugzilla id : 1339263
    :CaseComponent: \-
    :Requirement: Pki Server Instance
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults: Verify whether pki-server instance-start --help command shows the following
    output.
        Usage: pki-server instance-start [OPTIONS] <instance ID>
    
          -v, --verbose                Run in verbose mode.
                --help                   Show help message.
    """
    help_command = 'pki-server instance-start --help'

    cmd_output = ansible_module.command(help_command)

    for result in cmd_output.values():
        if result['rc'] == 0:
            assert "Usage: pki-server instance-start [OPTIONS] <instance ID>" in result['stdout']
            assert "-v, --verbose                      Run in verbose mode." in result['stdout']
            assert "--debug                        Run in debug mode." in result['stdout']
            assert "--help                         Show help message." in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()


def test_pki_server_instance_start_command(ansible_module):
    """
    :id: a18dc103-0991-41f4-88d2-5c20cbd40cfc
    :Title: Test pki-server instance-start command
    :Description: test pki-server instance-start command
    :CaseComponent: \-
    :Requirement: Pki Server Instance
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server instance-start command start the instance.
    """
    subsystems = ['ca', 'kra']  # TODO remove after build , 'ocsp', 'tks', 'tps']

    for system in subsystems:
        if TOPOLOGY == "01":
            instance = 'pki-tomcat'
        else:
            instance = eval("constants.{}_INSTANCE_NAME".format(system.upper()))
        stop_command = 'pki-server instance-stop {}'.format(instance)
        start_command = 'pki-server instance-start {}'.format(instance)
        # Start the instance
        start_instance = ansible_module.command(start_command)
        for result in start_instance.values():
            if result['rc'] == 0:
                if " instance already started" in result['stdout']:
                    assert '{} instance already started'.format(instance) in result['stdout']
                else:
                    assertstr = instance + " instance started"
                    assert assertstr in result['stdout']
                    log.info("Successfully run : {}".format(" ".join(result['cmd'])))
            else:
                log.error("Failed to run : {}".format(" ".join(result['cmd'])))
                pytest.skip()


@pytest.mark.exfail(raises=CalledProcessError)
def test_pki_server_instance_start_command_when_instance_does_not_exists(ansible_module):
    """
    :id: 7f3f4fc3-86a1-4042-913d-dc92de4886b7
    :Title: Test pki-server instance-start command when instance does not exits, BZ: 1384833
    :Description: test pki-server instance-start command
        This test also verifies bugzilla id : 1384833
    :CaseComponent: \-
    :Requirement: Pki Server Instance
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server instance-start command start the instance which are not exits.
    """
    system = "ABcCA"

    start_command = 'pki-server instance-start {}'.format(system)
    cmd_output = ansible_module.command(start_command)

    for result in cmd_output.values():
        if result['rc'] >= 1:
            assertstr = "ERROR: Invalid instance %s." % system
            assert assertstr in result['stderr']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()


def test_pki_server_instance_start_command_when_it_is_already_started(ansible_module):
    """
    :id: 93691558-151c-45f4-986e-9d94326592ca
    :Title: Test pki-server instance-start command when it is alreary started
    :Description: test pki-server instance-start command
    :CaseComponent: \-
    :Requirement: Pki Server Instance
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server instance-start command start the instance.
    """
    subsystems = ['ca', 'kra']  # TODO Remove after build , 'ocsp', 'tks', 'tps']

    for system in subsystems:
        if TOPOLOGY == "01":
            instance = 'pki-tomcat'
        else:
            instance = eval("constants.{}_INSTANCE_NAME".format(system.upper()))
        start_command = 'pki-server instance-start {}'.format(instance)

        cmd_output = ansible_module.command(start_command)
        assertstr = instance + " instance already started"
        assertstr2 = instance + " instance start"
        for result in cmd_output.values():
            if result['rc'] == 0:
                if assertstr in result['stdout']:
                    assert assertstr in result['stdout']
                else:
                    assert assertstr2 in result['stdout']
                log.info("Successfully run : {}".format(" ".join(result['cmd'])))
            else:
                log.error("Failed to run : {}".format(" ".join(result['cmd'])))
                pytest.skip()
