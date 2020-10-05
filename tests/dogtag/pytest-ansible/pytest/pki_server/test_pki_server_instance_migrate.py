"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI-SERVER CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki-server instance commands needs to be tested:
#   pki-server instance-migrate
#   pki-server instance-migrate --help
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


def test_pki_server_instance_migrate_help_command(ansible_module):
    """
    :id: 989538e6-3099-4f2c-a7e3-6bb849491162
    :Title: Test pki-server instance-migrate --help command, BZ:1339263
    :Description: test pki-server instance-migrate command, This command verifies the 
                  bugzilla id : 1339263
    :CaseComponent: \-
    :Requirement: Pki Server Instance 
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults: 
        1. Verify whether pki-server instance-migrate --help command shows the following output.

            Usage: pki-server instance-migrate [OPTIONS] <instance ID>
        
            --tomcat <version>       Use the specified Tomcat version.
            -v, --verbose                Run in verbose mode.
            --debug                  Show debug messages.
            --help                   Show help message.

    """
    help_cmd = 'pki-server instance-migrate --help'

    cmd_output = ansible_module.command(help_cmd)
    for result in cmd_output.values():
        if result['rc'] == 0:
            assert 'Usage: pki-server instance-migrate [OPTIONS] <instance ID>' in \
                   result['stdout']
            assert '--tomcat <version>       Use the specified Tomcat version.' in \
                   result['stdout']
            assert '-v, --verbose                Run in verbose mode.' in result['stdout']
            assert '--debug                  Show debug messages.' in result['stdout']
            assert '--help                   Show help message.' in result['stdout']
        else:
            pytest.skip("Failed to run pki-server instance-migrate --help command.")


def test_pki_server_instance_migrate_without_tomcat_command(ansible_module):
    """
    :id: b03eaa9e-4ad1-4c1f-ae6c-12d8629d6ca7
    :Title: Test pki-server instance-migrate without tomcat, BZ:1348433
    :Description: pki-server instance-migrate command This test also verifies bugzilla id : 1348433
    :Requirement: Pki Server Instance
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :ExpectedResults:
        1. Verify whether pki-server instance-migrate command migrate the instance
        without tomcat version.
    """
    # Store command in variable
    migrate = 'pki-server instance-migrate {} --tomcat'.format(constants.CA_INSTANCE_NAME)

    cmd_output = ansible_module.command(migrate)
    for result in cmd_output.values():
        if result['rc'] >= 1:
            assert "ERROR: option --tomcat requires argument" in result['stderr']
            assert 'Usage: pki-server instance-migrate [OPTIONS] <instance ID>' in \
                   result['stdout']
            assert '--tomcat <version>       Use the specified Tomcat version.' in \
                   result['stdout']
            assert '-v, --verbose                Run in verbose mode.' in result['stdout']
            assert '--debug                  Show debug messages.' in result['stdout']
            assert '--help                   Show help message.' in result['stdout']
        else:
            pytest.skip("Failed to run pki-server instance-migrate without tomcat version.")


@pytest.mark.skip(reason="pki-servlet-container is not supported in Rhel 8.2")
def test_pki_server_instance_migrate_command(ansible_module):
    """
    :id: 9f101b62-9ba2-4b88-bea1-a75bac9f694f
    :Title: Test pki-server instance-migrate command
    :Description: Test pki-server instance-migrate command
    :Requirement: Pki Server Instance
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server instance-migrate command migrate,
        2. All the instances to the next or previous tomcat version if it is supported by
           RHEL and CS.
    """
    # Store subsystems in list
    subsystems = ['ca', 'kra']  # TODO remove after build, 'ocsp', 'tks', 'tps']

    # Check tomcat version.
    rpm_cmd = 'rpm -qa pki-servlet-container'
    cmd_output = ansible_module.command(rpm_cmd)
    version = None
    for result in cmd_output.values():
        if result['rc'] == 0:
            version = int(result['stdout'].split("-")[3].split(".")[0])

    for system in subsystems:
        if TOPOLOGY == '01':
            instance = 'pki-tomcat'
            topology_name = 'topology-01-CA'
        else:
            instance = eval("constants.{}_INSTANCE_NAME".format(system.upper()))
            topology_name = constants.CA_INSTANCE_NAME
        cmd_output = ansible_module.command('pki-server instance-migrate '
                                            '--tomcat {} {}'.format(str(version + 1), instance))
        for res in cmd_output.values():
            if res['rc'] == 0:
                assert instance + " instance migrated" in res['stdout']

            else:
                pytest.skip("Failed to run pki-server instance-start " + instance + " command")
        else:
            ansible_module.command('pki-server instance-migrate '
                                   '--tomcat {} {}'.format(str(version - 1), instance))
