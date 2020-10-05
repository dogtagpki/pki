"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI-SERVER CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki-server kra-db-vlv-del commands needs to be tested:
#   pki-server kra-db-vlv-del --help
#   pki-server kra-db-vlv-del
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


@pytest.mark.parametrize('args', ['--help', '', 'asdfa'])
def test_pki_server_kra_db_vlv_del_help(ansible_module, args):
    """
    :Title: Test pki-server kra-db-vlv-del --help commands
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement: RHCS-REQ KRA Server CLI Tests
    :ExpectedResults:
        1. Verify whether pki-server kra-db-vlv-del --help command shows the following commands.

    Usage: pki-server kra-db-vlv-del [OPTIONS]

      -i, --instance <instance ID>       Instance ID (default: pki-tomcat).
      -D, --bind-dn <Bind DN>            Connect DN (default: cn=Directory Manager).
      -w, --bind-password <password>     Password to connect to DB.
      -v, --verbose                      Run in verbose mode.
      -g, --generate-ldif <outfile>      Generate LDIF of required changes.
          --help                         Show help message.
    """
    help_message = ansible_module.command('pki-server kra-db-vlv-del {}'.format(args))

    for result in help_message.values():
        if result['rc'] == 0:
            assert "Usage: pki-server kra-db-vlv-del [OPTIONS]" in result['stdout']
            assert "-i, --instance <instance ID>       Instance ID (default: pki-tomcat)." in result['stdout']
            assert "-D, --bind-dn <Bind DN>            Connect DN (default: cn=Directory Manager)." in result['stdout']
            assert "-w, --bind-password <password>     Password to connect to database." in result['stdout']
            assert "-g, --generate-ldif <outfile>      Generate LDIF of required changes." in result['stdout']
            assert "-v, --verbose                      Run in verbose mode." in result['stdout']
            assert "--help                         Show help message." in result['stdout']
            log.info("Successfully run {}".format(result['cmd']))
        elif args in ['', 'asdfa']:
            assert 'ERROR: Invalid instance pki-tomcat.' in result['stderr']
            log.info("Successfully run {}".format(result['cmd']))
        else:
            pytest.fail("Failed to run {}".format(result['cmd']))


def test_pki_server_kra_db_vlv_del_command(ansible_module):
    """
    :Title: Test pki-server kra-db-vlv-del command
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement: RHCS-REQ KRA Server CLI Tests
    :Steps:
        1. run pki-server kra-db-vlv-del -i <instance> -D <base_dn> -w <password>
    :ExpectedResults:
        1. Verify whether VLV index to the database and generate the .ldif file of VLV index.
    """

    out = ansible_module.command('pki-server kra-db-vlv-del -i {} -D "{}" -w {}'.format(kra_instance_name,
                                                                                        constants.LDAP_BIND_DN,
                                                                                        constants.LDAP_PASSWD))

    for result in out.values():
        if result['rc'] == 0:
            assert "KRA VLVs deleted from the database for " + kra_instance_name
            log.info("Successfully run {}".format(result['cmd']))
        else:
            pytest.xfail("Failed to run {}".format(result['cmd']))


def test_pki_server_kra_db_vlv_del_when_already_deleted(ansible_module):
    """
    :Title: Test pki-server kra-db-vlv-del command when VLV index already deleted.
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement: RHCS-REQ KRA Server CLI Tests
    :Steps:
        1. pki-server kra-db-vlv-del -i <instance> -D <base_dn> -w <password>
    :ExpectedResults:
        1. Verify whether VLV index to the database and generate the .ldif file of VLV index.
    """

    cmd_out = ansible_module.command('pki-server kra-db-vlv-del -i {} -D "{}" -w {}'.format(kra_instance_name,
                                                                                            constants.LDAP_BIND_DN,
                                                                                            constants.LDAP_PASSWD))

    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "KRA VLVs deleted from the database for " + kra_instance_name in result['stdout']
            log.info("Successfully run {}".format(result['cmd']))
        else:
            pytest.xfail("Failed to run {}".format(result['cmd']))


def test_pki_server_kra_db_vlv_del_when_vlv_reindexed(ansible_module):
    """
    :Title: Test pki-server kra-db-vlv-del when VLV already reindexed.
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement: RHCS-REQ KRA Server CLI Tests
    :ExpectedResults:
        Verify whether command del VLV index to the database when vlv records are reindexed.
    """
    vlv_del_cmd = 'pki-server kra-db-vlv-del -i {} -D "{}" -w {}'.format(kra_instance_name,
                                                                         constants.LDAP_BIND_DN, constants.LDAP_PASSWD)

    vlv_reindex_cmd = 'pki-server kra-db-vlv-reindex -i {} -D "{}" -w {}'.format(kra_instance_name,
                                                                                 constants.LDAP_BIND_DN,
                                                                                 constants.LDAP_PASSWD)

    vlv_reindex = ansible_module.command(vlv_reindex_cmd)
    for result in vlv_reindex.values():
        if result['rc'] == 0:
            assert "Initiating KRA VLV reindex for " + kra_instance_name in result['stdout']
            assert "KRA VLV reindex completed for " + kra_instance_name in result['stdout']
            log.info("Reindexing completed.")
        else:
            pytest.fail("Failed to run kra-db-vlv-reindex for deleting.")

    vlv_del_out = ansible_module.command(vlv_del_cmd)
    for result in vlv_del_out.values():
        if result['rc'] == 0:
            assert "KRA VLVs deleted from the database for " + kra_instance_name in result['stdout']
            log.info("Successfully run {}".format(result['cmd']))

        else:
            log.info(result['stdout'])
            log.info(result['stderr'])
            pytest.fail("Failed to run pki-server kra-db-vlv-del command")


def test_pki_server_kra_db_vlv_del_with_ldif_file(ansible_module):
    """
    :Title: Test pki-server kra-db-vlv-del with ldif file.
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement: RHCS-REQ KRA Server CLI Tests
    :ExpectedResults:
        1. Verify VLV index to the database and generate the .ldif file of VLV index.
    """

    file_name = "testfile.ldif"
    vlv_del_cmd = 'pki-server kra-db-vlv-del -i {} -D "{}" -w {} -g {}'.format(kra_instance_name,
                                                                               constants.LDAP_BIND_DN,
                                                                               constants.LDAP_PASSWD, file_name)

    vlv_del_result = ansible_module.command(vlv_del_cmd)
    for result in vlv_del_result.values():
        if result['rc'] == 0:
            assert "KRA VLV changes written to " + file_name in result['stdout']
            assert "KRA VLVs deleted from the database for " + kra_instance_name in result['stdout']

            file_stat = ansible_module.stat(path=file_name)
            for result1 in file_stat.values():
                assert result1['stat']['exists'] == True
            log.info("Successfully run {}".format(result['cmd']))

        else:
            log.info(result['stdout'])
            log.info(result['stderr'])
            pytest.fail("Failed to run {}.".format(result['cmd']))


def test_pki_server_kra_db_vlv_del_when_instance_stop(ansible_module):
    """
    :Title: Test pki-server kra-db-vlv-del when instance is stopped.
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement: RHCS-REQ KRA Server CLI Tests
    :Steps:
        1. pki-server kra-db-vlv-del -i <instance> -D <binddn> -w <password>
    :ExpectedResults:
        1. Verify whether command delete VLV index to the database and generate the .ldif file
        of VLV index when instance is stopped.
    """

    vlv_del_cmd = 'pki-server kra-db-vlv-del -i {} -D "{}" -w {}'.format(kra_instance_name,
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
            log.info(result['stdout'])
            log.info(result['stderr'])
            pytest.fail("Failed to stop the instance.")

    vlv_del_result = ansible_module.command(vlv_del_cmd)
    for result in vlv_del_result.values():
        if result['rc'] == 0:
            assert "KRA VLVs deleted from the database for " + kra_instance_name in result['stdout']
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
            log.info(result['stdout'])
            log.info(result['stderr'])
            pytest.fail("Failed to start instance.")


def test_pki_server_kra_db_vlv_del_when_invalid_dn(ansible_module):
    """
    :Title: Test pki-server kra-db-vlv-del when invalid DN is provided.
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement: RHCS-REQ KRA Server CLI Tests
    :Steps:
        1. pki-server kra-db-vlv-del -i <instance> -D "cn=Directory manager" -w <password>
    :ExpectedResults:
        1. Verify whether command not del VLV index to the database and generate the .ldif
        file of VLV index when invalid dn is specified it throws the error.
    """

    vlv_del_cmd = 'pki-server kra-db-vlv-del -i {} -D "cn=Directory manager123" ' \
                  '-w {}'.format(kra_instance_name, constants.LDAP_PASSWD)
    vlv_del_result = ansible_module.command(vlv_del_cmd)

    for result in vlv_del_result.values():
        if result['rc'] == 0:
            assert "KRA VLVs deleted from the database for " + kra_instance_name in result['stdout']
            log.info(result['stdout'])
            log.info(result['stderr'])
            pytest.fail("Successfully run {}".format(result['cmd']))

        else:
            log.info("Failed to run {}.".format(result['cmd']))


def test_pki_server_kra_db_vlv_del_when_invalid_password(ansible_module):
    """
    :Title: Test pki-server kra-db-vlv-del when invalid password is provided.
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement: RHCS-REQ KRA Server CLI Tests
    :Steps:
        1. pki-server kra-db-vlv-del -i <instance> -D <invalid dn> -w <password>
    :ExpectedResults:
        1. Verify whether not del VLV index to the database and generate the .ldif file of VLV
        index when invalid password is specified it throws the error.
    """

    vlv_del_cmd = 'pki-server kra-db-vlv-del -i {} -D "cn=Directory manager" ' \
                  '-w {}12312'.format(kra_instance_name, constants.LDAP_PASSWD)
    vlv_del_result = ansible_module.command(vlv_del_cmd)

    for result in vlv_del_result.values():
        if result['rc'] == 0:
            assert "KRA VLVs deleted from the database for " + kra_instance_name in result['stdout']
            log.info(result['stdout'])
            log.info(result['stderr'])
            pytest.fail("Successfully run {}".format(result['cmd']))

        else:
            log.info("Failed to run {}.".format(result['cmd']))
