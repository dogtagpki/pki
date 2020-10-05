"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI-SERVER CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki-server kra-db-vlv commands needs to be tested:
#   pki-server kra-db-vlv-add --help
#   pki-server kra-db-vlv-add
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Amol Kahat <akahat@redhat.com>
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


@pytest.mark.parametrize('args', ['--help', '', 'asdfa'])
def test_pki_server_kra_db_vlv_add_help(ansible_module, args):
    """
    :Title: Test pki-server kra-db-vlv-add --help command
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement: RHCS-REQ KRA Server CLI Tests
    :ExpectedResults: Verify whether pki-server kra-db-vlv-add --help command shows the following commands.
        Usage: pki-server kra-db-vlv-add [OPTIONS]
    
          -i, --instance <instance ID>       Instance ID (default: pki-tomcat).
          -D, --bind-dn <Bind DN>            Connect DN (default: cn=Directory Manager).
          -w, --bind-password <password>     Password to connect to DB.
          -v, --verbose                      Run in verbose mode.
          -g, --generate-ldif <outfile>      Generate LDIF of required changes.
              --help                         Show help message.
    """
    server_out = ansible_module.command('pki-server kra-db-vlv-add {}'.format(args))
    for result in server_out.values():
        if result['rc'] == 0:
            assert "Usage: pki-server kra-db-vlv-add [OPTIONS]" in result['stdout']
            assert "-i, --instance <instance ID>       Instance ID (default: pki-tomcat)." in result['stdout']
            assert "-D, --bind-dn <Bind DN>            Connect DN (default: cn=Directory Manager)." in result['stdout']
            assert "-w, --bind-password <password>     Password to connect to database." in result['stdout']
            assert "-v, --verbose                      Run in verbose mode." in result['stdout']
            assert "-g, --generate-ldif <outfile>      Generate LDIF of required changes." in result['stdout']
            assert "--help                         Show help message." in result['stdout']
            log.info("Successfully run {}".format(result['cmd']))
        elif args in ['', 'asdfa']:
            assert 'ERROR: Invalid instance pki-tomcat.' in result['stderr']
            log.info("Successfully run {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail("Failed to run {}".format(result['cmd']))


def test_pki_server_kra_db_vlv_add_command(ansible_module):
    """
    :Title: Test pki-server kra-db-vlv-add command

    :Test: test pki-server kra-db-vlv-add command

    :Setup: Use the subsystems setup in ansible to run subsystem commands

    :Requirement: RHCS-REQ KRA Server CLI Tests

    :ExpectedResults: Verify whether pki-server kra-db-vlv-add command add VLV index
    to the database and generate the .ldif file of VLV index.
    """
    file_name = "/tmp/{}.ldif".format(kra_instance_name)
    cmd = 'pki-server kra-db-vlv-add -i {} -D "cn=Directory Manager" ' \
          '-w {} -g {}'.format(kra_instance_name, constants.LDAP_PASSWD, file_name)
    result_out = ansible_module.command(cmd)
    for result in result_out.values():
        if result['rc'] == 0:
            assert "KRA VLVs written to " + file_name in result['stdout']
            file_stat = ansible_module.stat(path=file_name)
            for result1 in file_stat.values():
                assert result1['stat']['exists'] == True
            log.info("Successfully run {}".format(result['cmd']))
        else:
            log.error("Failed to run {}".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


def test_pki_server_kra_db_vlv_add_when_already_added(ansible_module):
    """
    :Title: Test pki-server kra-db-vlv-add command when VLV index already added.
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement: RHCS-REQ KRA Server CLI Tests
    :ExpectedResults:
        1. VLV index should get added to the database.
        2. It should generate the .ldif file of VLV index.
    """
    file_name = "/tmp/{}.ldif".format(kra_instance_name)
    cmd = 'pki-server kra-db-vlv-add -i {} -D "cn=Directory Manager" ' \
          '-w {} -g {}'.format(kra_instance_name, constants.LDAP_PASSWD, file_name)
    result_out1 = ansible_module.command(cmd)
    for result1 in result_out1.values():
        if result1['rc'] == 0:
            assert "KRA VLVs written to " + file_name in result1['stdout']
    result_out = ansible_module.command(cmd)
    for result in result_out.values():
        if result['rc'] == 0:
            assert "KRA VLVs written to " + file_name in result['stdout']
            file_stat = ansible_module.stat(path=file_name)
            for result1 in file_stat.values():
                assert result1['stat']['exists'] == True
            log.info("Successfully run {}".format(result['cmd']))
        else:
            log.error("Failed to run {}".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


def test_pki_server_kra_db_vlv_add_when_instance_stop(ansible_module):
    """
    :Title: Test pki-server kra-db-vlv-add when instance is stopped.
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement: RHCS-REQ KRA Server CLI Tests
     :ExpectedResults:
        1. VLV index should get added to the database.
        2. It should generate the .ldif file of VLV index.
    """

    file_name = "/tmp/{}.ldif".format(kra_instance_name)
    cmd = 'pki-server kra-db-vlv-add -i {} -D "cn=Directory Manager" ' \
          '-w {} -g {}'.format(kra_instance_name, constants.LDAP_PASSWD, file_name)

    cmd_out = ansible_module.command('pki-server instance-stop {}'.format(kra_instance_name))
    for res in cmd_out.values():
        if res['rc'] == 0:
            assert "{} instance stopped".format(kra_instance_name) in res['stdout']
            log.info(res['stdout'])
        else:
            log.error(res['stdout'])
            log.error(res['stderr'])
            pytest.fail()

    result_out = ansible_module.command(cmd)
    for result in result_out.values():
        if result['rc'] == 0:
            assert "KRA VLVs written to " + file_name in result['stdout']
            file_stat = ansible_module.stat(path=file_name)
            for result1 in file_stat.values():
                assert result1['stat']['exists'] == True
            log.info("Successfully run {}".format(result['cmd']))
        else:
            log.error("Failed to run {}".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    cmd_out = ansible_module.command('pki-server instance-start {}'.format(kra_instance_name))
    for res in cmd_out.values():
        if res['rc'] == 0:
            assert "{} instance started".format(kra_instance_name) in res['stdout']
            log.info(res['stdout'])
        else:
            log.error(res['stdout'])
            log.error(res['stderr'])
            pytest.fail()


def test_pki_server_kra_db_vlv_add_when_invalid_dn(ansible_module):
    """
    :Title: Test pki-server kra-db-vlv-add when invalid DN is provided.

    :Test: test pki-server kra-db-vlv-add command

    :Setup: Use the subsystems setup in ansible to run subsystem commands

    :Requirement: RHCS-REQ KRA Server CLI Tests

    :ExpectedResults: Verify whether pki-server kra-db-vlv-add command not add VLV
    index to the database and generate the .ldif file of VLV index when
    invalid dn is specified it throws the error.
    """
    file_name = "/tmp/{}.ldif".format(kra_instance_name)
    cmd = 'pki-server kra-db-vlv-add -i {} -D "cn=Directory Manager123" ' \
          '-w {} -g {}'.format(kra_instance_name, constants.LDAP_PASSWD, file_name)
    result_out1 = ansible_module.command(cmd)
    for result1 in result_out1.values():
        if result1['rc'] == 0:
            assert "KRA VLVs written to " + file_name in result1['stdout']
    result_out = ansible_module.command(cmd)
    for result in result_out.values():
        if result['rc'] == 0:
            log.error("Failed to run {}".format(result['cmd']))
            log.error("Refer BZ: 1706687")
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.skip()
            assert "Invalid Credentials" in result['stdout']
        else:
            log.info("Successfully run {}".format(result['cmd']))


def test_pki_server_kra_db_vlv_add_when_invalid_password(ansible_module):
    """
    :Title: Test pki-server kra-db-vlv-add when invalid password provided.

    :Test: test pki-server kra-db-vlv-add command

    :Setup: Use the subsystems setup in ansible to run subsystem commands

    :Requirement: RHCS-REQ KRA Server CLI Tests

    :ExpectedResults: Verify whether pki-server kra-db-vlv-add command not add VLV
    index to the database and generate the .ldif file of VLV index when
    invalid password is specified it throws the error.
    """

    file_name = "/tmp/{}.ldif".format(kra_instance_name)
    cmd = 'pki-server kra-db-vlv-add -i {} -D "cn=Directory Manager" ' \
          '-w {}213 -g {}'.format(kra_instance_name, constants.LDAP_PASSWD, file_name)
    result_out1 = ansible_module.command(cmd)
    for result1 in result_out1.values():
        if result1['rc'] == 0:
            assert "KRA VLVs written to " + file_name in result1['stdout']
    result_out = ansible_module.command(cmd)
    for result in result_out.values():
        if result['rc'] == 0:

            log.error("Failed to run {}".format(result['cmd']))
            log.error("Refer BZ: 1706687")
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.skip()
            assert "Invalid Credentials" in result['stdout']
        else:
            log.info("Successfully run {}".format(result['cmd']))
