"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI-SERVER CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki-server commands needs to be tested:
#   pki-server migrate 
#   pki-server migrate --help
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

TOPOLOGY = constants.CA_INSTANCE_NAME.split("-")[-2]
log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)


def test_pki_server_migrate_help_command(ansible_module):
    """
    :id: 3f7defc2-7494-4f07-9942-702cf50a93fc
    :Title: Test pki-server migrate --help command.
    :Description: test pki-server migrate command, This test also verifies bugzilla id : 1339263
    :CaseComponent: \-
    :Requirement: Pki Server Migrate
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults: 
        1. Verify whether pki-server migrate --help command shows the following options.
            Usage: pki-server migrate [OPTIONS]
        
                  --tomcat <version>       Use the specified Tomcat version.
              -v, --verbose                Run in verbose mode.
                  --debug                  Show debug messages.
                  --help                   Show help message.
    """

    cmd_output = ansible_module.command('pki-server migrate --help')
    for result in cmd_output.values():
        if result['rc'] == 0:
            assert "Usage: pki-server migrate [OPTIONS" in result['stdout']
            assert "--tomcat <version>       Use the specified Tomcat version." in result['stdout']
            assert "-v, --verbose                Run in verbose mode." in result['stdout']
            assert "--debug                  Show debug messages." in result['stdout']
            assert "--help                   Show help message." in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()

@pytest.mark.skip(reason="pki-servlet-container is not supported in Rhel 8.2")
def test_pki_server_migrate_command(ansible_module):
    """
    :id: 2659a948-ed42-4564-b89a-781858e23a8a
    :Title: Test pki-server migrate command
    :Description: test pki-server migrate command
    :CaseComponent: \-
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server migrate command migrate the all the instances to the
            next or previous tomcat version if it is supported by RHEL and CS.
    """
    version = None
    cmd_output = ansible_module.command('rpm -qa pki-servlet-container')
    for result in cmd_output.values():
        if result['rc'] == 0:
            version = result['stdout'].split("-")[3].split(".")[0]
            version_old = int(version)
            version_new = version_old + 1

            cmdstr = "pki-server migrate --tomcat {}"
            if version_old < 8:
                cmd_output = ansible_module.command(cmdstr.format(version_new))
                for res in cmd_output.values():
                    if res['rc'] == 0:
                        assert "System migrated" in res['stdout']
                        log.info("Successfully run : {}".format(" ".join(res['cmd'])))

            else:
                cmd_output = ansible_module.command(cmdstr.format(version_old))
                for res in cmd_output.values():
                    if res['rc'] == 0:
                        assert "System migrated" in res['stdout']
                        log.info("Successfully run : {}".format(" ".join(res['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()
        ansible_module.command('pki-server migrate --tomcat {}'.format(version))
