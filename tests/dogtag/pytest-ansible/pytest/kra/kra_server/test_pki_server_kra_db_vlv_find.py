"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI-SERVER CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki-server kra-db-vlv commands needs to be tested:
#   pki-server kra-db-vlv-find --help
#   pki-server kra-db-vlv-find
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Amol Kahat <akahat@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2016 Red Hat, Inc. All rights reserved.
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

from pki.testlib.common.utils import UserOperations

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

user_op = UserOperations(nssdb=constants.NSSDB)
log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)

TOPOLOGY = constants.CA_INSTANCE_NAME.split("-")[-2]

if TOPOLOGY == '01':
    kra_instance_name = 'pki-tomcat'
    topology_name = 'topology-01-CA'
else:
    kra_instance_name = constants.KRA_INSTANCE_NAME
    topology_name = constants.CA_INSTANCE_NAME


@pytest.mark.parametrize('args', ['asdfa', '', '--help'])
def test_pki_server_kra_db_vlv_find_help(ansible_module, args):
    """
    :Title: Test pki-server kra-db-vlv-find --help command
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement: RHCS-REQ KRA Server CLI Tests
    :ExpectedResults:
        1. Verify whether pki-server kra-db-vlv-find --help command shows the following commands.

    Usage: pki-server kra-db-vlv-find [OPTIONS]

      -i, --instance <instance ID>       Instance ID (default: pki-tomcat).
      -D, --bind-dn <Bind DN>            Connect DN (default: cn=Directory Manager).
      -w, --bind-password <password>     Password to connect to database.
      -v, --verbose                      Run in verbose mode.
          --help                         Show help message.
    """

    help_cmd = 'pki-server kra-db-vlv-find {}'.format(args)

    help_out = ansible_module.command(help_cmd)
    for result in help_out.values():
        if result['rc'] == 0:
            assert "Usage: pki-server kra-db-vlv-find [OPTIONS]\n" in result['stdout']
            assert "-i, --instance <instance ID>       Instance ID (default: pki-tomcat)." in result['stdout']
            assert "-D, --bind-dn <Bind DN>            Connect DN (default: cn=Directory Manager)." in result['stdout']
            assert "-w, --bind-password <password>     Password to connect to database." in result['stdout']
            assert "-v, --verbose                      Run in verbose mode." in result['stdout']
            assert "    --help                         Show help message." in result['stdout']
            log.info("Successfully run {}".format(result['cmd']))
        elif args in ['', 'asdfa']:
            assert 'ERROR: Invalid instance pki-tomcat' in result['stderr']
            log.info("Successfully run {}".format(result['cmd']))
        else:
            log.info(result['stdout'])
            log.info(result['stderr'])
            pytest.fail("Failed to run {}".format(result['cmd']))


def test_pki_server_kra_db_vlv_find_command(ansible_module):
    """
    :Title: Test pki-server kra-db-vlv-find command
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement: RHCS-REQ KRA Server CLI Tests
    :ExpectedResults:
        1. Verify whether cmd find VLV index to the database.
    """
    vlv_find = 'pki-server kra-db-vlv-find -i {} -D "{}" -w {}'.format(kra_instance_name,
                                                                       constants.LDAP_BIND_DN, constants.LDAP_PASSWD)
    vlv_out = ansible_module.command(vlv_find)
    for result in vlv_out.values():
        if result['rc'] == 0:
            if "0 entries found" in result['stdout']:
                log.info("Successfully run {}.".format(result['cmd']))
            elif " entries found" in result['stdout']:
                assert "objectClass: top" in result['stdout']
                assert "objectClass: vlvSearch" in result['stdout']
                assert "vlvScope:" in result['stdout']
                assert "vlvFilter:" in result['stdout']
                assert "vlvBase:" in result['stdout']
                assert "vlvUses:" in result['stdout']
                assert "vlvEnabled:" in result['stdout']
                log.info("Successfully run {}.".format(result['cmd']))
        else:
            log.info(result['stdout'])
            log.info(result['stderr'])
            pytest.fail("Failed to run {}".format(result['cmd']))


def test_pki_server_kra_db_vlv_find_when_instance_stop(ansible_module):
    """
    :Title: Test pki-server kra-db-vlv-find when instance is stopped.
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement: RHCS-REQ KRA Server CLI Tests
    :Steps:
        1.
    :ExpectedResults:
        1. Verify whether pki-server kra-db-vlv-find command find VLV index to the database and show
        VLV index when instance is stopped.
    """
    vlv_find_cmd = 'pki-server kra-db-vlv-find -i {} -D "{}" -w {}'.format(kra_instance_name,
                                                                           constants.LDAP_BIND_DN,
                                                                           constants.LDAP_PASSWD)

    start_instance = 'pki-server instance-start {}'.format(kra_instance_name)
    stop_instance = 'pki-server instance-stop {}'.format(kra_instance_name)

    stop_out = ansible_module.command(stop_instance)
    for result in stop_out.values():
        if result['rc'] == 0:
            if 'already stopped' in result['stdout']:
                assert kra_instance_name + " instance already stopped" in result['stdout']
            else:
                assert kra_instance_name + " instance stopped" in result['stdout']
        else:
            pytest.fail("Failed to stop the instance.")

    vlv_del_result = ansible_module.command(vlv_find_cmd)
    for result in vlv_del_result.values():
        if result['rc'] == 0:
            if "0 entries found" in result['stdout']:
                log.info("Successfully run {}.".format(result['cmd']))
            elif " entries found" in result['stdout']:
                assert "objectClass: top" in result['stdout']
                assert "objectClass: vlvSearch" in result['stdout']
                assert "vlvScope:" in result['stdout']
                assert "vlvFilter:" in result['stdout']
                assert "vlvBase:" in result['stdout']
                assert "vlvUses:" in result['stdout']
                assert "vlvEnabled:" in result['stdout']
                log.info("Successfully run {}.".format(result['cmd']))
        else:
            log.info(result['stdout'])
            log.info(result['stderr'])
            pytest.fail("Failed to run {}".format(result['cmd']))

    inst_start = ansible_module.command(start_instance)
    for result in inst_start.values():
        if result['rc'] == 0:
            assert kra_instance_name + " instance started" in result['stdout']
        else:
            pytest.fail("Failed to start instance.")


def test_pki_server_kra_db_vlv_find_when_invalid_dn(ansible_module):
    """
    :Title: Test pki-server kra-db-vlv-find with invalid DN is provided.
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement: RHCS-REQ KRA Server CLI Tests
    :ExpectedResults:
        1. Verify whether command not find VLV index to the database and generate VLV
        index when invalid dn is specified it throws the error.
    """
    vlv_find_cmd = 'pki-server kra-db-vlv-find -i {} -D "cn=Directory manager123" ' \
                   '-w {}'.format(kra_instance_name, constants.LDAP_PASSWD)
    vlv_find_result = ansible_module.command(vlv_find_cmd)

    for result in vlv_find_result.values():
        if result['rc'] == 0:
            if "0 entries found" in result['stdout']:
                log.info("Successfully run {}.".format(result['cmd']))
            elif " entries found" in result['stdout']:
                assert "objectClass: top" in result['stdout']
                assert "objectClass: vlvSearch" in result['stdout']
                assert "vlvScope:" in result['stdout']
                assert "vlvFilter:" in result['stdout']
                assert "vlvBase:" in result['stdout']
                assert "vlvUses:" in result['stdout']
                assert "vlvEnabled:" in result['stdout']
                log.info("Successfully run {}.".format(result['cmd']))
        else:
            log.info("Failed to run {}.".format(result['cmd']))


def test_pki_server_kra_db_vlv_find_when_invalid_password(ansible_module):
    """
    :Title: Test pki-server kra-db-vlv-find when invalid password provided.
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement: RHCS-REQ KRA Server CLI Tests
    :ExpectedResults:
        1. Verify whether pki-server kra-db-vlv-find command not find VLV index to the database.
        When invalid password is specified it throws the error.
    """

    vlv_find_cmd = 'pki-server kra-db-vlv-find -i {} -D "cn=Directory manager" ' \
                   '-w {}12312'.format(kra_instance_name, constants.LDAP_PASSWD)
    vlv_del_result = ansible_module.command(vlv_find_cmd)

    for result in vlv_del_result.values():
        if result['rc'] == 0:
            if "0 entries found" in result['stdout']:
                log.info("Successfully run {}.".format(result['cmd']))
            elif " entries found" in result['stdout']:
                assert "objectClass: top" in result['stdout']
                assert "objectClass: vlvSearch" in result['stdout']
                assert "vlvScope:" in result['stdout']
                assert "vlvFilter:" in result['stdout']
                assert "vlvBase:" in result['stdout']
                assert "vlvUses:" in result['stdout']
                assert "vlvEnabled:" in result['stdout']
                log.info("Successfully run {}.".format(result['cmd']))
        else:
            log.info("Failed to run {}.".format(result['cmd']))
