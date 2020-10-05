"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI-SERVER CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki-server instance-find commands needs to be tested:
#   pki-server instance-find --help
#   pki-server instance-find
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
log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)

TOPOLOGY = constants.CA_INSTANCE_NAME.split("-")[-2]

if TOPOLOGY == '01':
    ca_instance_name = 'pki-tomcat'
    topology_name = 'topology-01-CA'
else:
    ca_instance_name = constants.CA_INSTANCE_NAME
    topology_name = constants.CA_INSTANCE_NAME


def test_pki_server_instance_find_command_with_help(ansible_module):
    """
    :id: 9c21a336-17ca-4565-bb28-c66c789fb56e
    :Title: Test pki-server instance-find --help command, BZ: 1339263
    :Description: test pki-server instance-find --help command,  This test also verifies
                  bugzilla id : 1339263
    :CaseComponent: \-
    :Requirement: Pki Server Instance
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults: 
        1. Verify whether pki-server instance-find --help command shows the following commands.

        Usage: pki-server instance-find [OPTIONS]

          -v, --verbose                Run in verbose mode.
                --help                   Show help message.
    """
    help_command = 'pki-server instance-find --help'

    cmd_output = ansible_module.command(help_command)
    for result in cmd_output.values():
        if result['rc'] >= 1:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()
        else:
            assert "Usage: pki-server instance-find [OPTIONS]" in result['stdout']
            assert "-v, --verbose                      Run in verbose mode." in result['stdout']
            assert "--debug                        Run in debug mode." in result['stdout']
            assert "--help                         Show help message." in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))


def test_pki_server_instance_find_command(ansible_module):
    """
    :id: 37b93717-7968-4d85-8eff-7aaca9329f68
    :Title: Test pki-server instance-find command
    :Description: test pki-server instance-find command
    :Requirement: Pki Server Instance
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :CaseComponent: \-
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server instance-find command shows the instace name and state.
    """
    subsystems = ['ca', 'kra']  # TODO remove after build , 'ocsp', 'tks', 'tps']

    cmd_output = ansible_module.command('pki-server instance-find')
    for result in cmd_output.values():
        if result['rc'] == 0:
            for system in subsystems:
                if TOPOLOGY == "01":
                    instance = 'pki-tomcat'
                else:
                    instance = eval("constants.{}_INSTANCE_NAME".format(system.upper()))

                assertsuccess = "Instance ID: " + instance
                try:
                    assert assertsuccess in result['stdout']
                except CalledProcessError as e:
                    log.error("Failed to find the instance.")
                    pytest.skip()
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()


def test_pki_server_instance_find_with_more_instance_stopped(ansible_module):
    """
    :id: 9cedb8b2-40cc-4204-9d9b-c889e5fe3fef
    :Title: Test pki-server instance-find command when one or more instance is stopped
    :Description: test pki-server instance-find command
    :CaseComponent: \-
    :Requirement: Pki Server Instance
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server instance-find command shows the instace name and state.
    """
    subsystems = ['ca', 'kra']  # TODO remove after build 'ocsp', 'tks', 'tps']
    instance = None
    for system in subsystems:
        if TOPOLOGY == "01":
            instance = 'pki-tomcat'
        else:
            instance = eval("constants.{}_INSTANCE_NAME".format(system.upper()))

        ansible_module.command('pki-server instance-stop {}'.format(instance))

    cmd_output = ansible_module.command('pki-server instance-find')
    for result in cmd_output.values():
        if result['rc'] == 0:
            for system in subsystems:
                if TOPOLOGY == "01":
                    instance = 'pki-tomcat'
                else:
                    instance = eval("constants.{}_INSTANCE_NAME".format(system.upper()))

                assertInstanceID = "Instance ID: {}".format(instance)
                assertFalse = "Active: False"
                try:
                    assert assertInstanceID in result['stdout']
                    assert assertFalse in result['stdout']
                except CalledProcessError:
                    pytest.skip("Failed to run pki-server instance-find command")

    for system in subsystems:
        instance = None
        try:
            instance = eval("constants.{}_INSTANCE_NAME".format(system.upper()))
        except:
            pytest.skip("Instance is not present")

        ansible_module.command('pki-server instance-start {}'.format(instance))
