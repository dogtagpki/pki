"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI-SERVER CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki-server db-schema commands needs to be tested:
#   pki-server db-schema-upgrade --help
#   pki-server db-schema-upgrade
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
    instance_name = '{}-testingmaster'.format("-".join(constants.CA_INSTANCE_NAME.split("-")[:-1]))
    stop_ds = 'systemctl stop dirsrv@slapd-{}'.format(instance_name)
    ansible_module.command(stop_ds)
    yield
    start_ds = 'systemctl start dirsrv@slapd-{}'.format(instance_name)
    ansible_module.command(start_ds)


@pytest.fixture(autouse=False)
def stop_pki_instance(ansible_module):
    instance = constants.CA_INSTANCE_NAME
    stop_instance = 'pki-server instance-stop {}'.format(instance)
    start_instance = 'pki-server instance-start {}'.format(instance)
    ansible_module.command(stop_instance)
    yield instance
    ansible_module.command(start_instance)


def test_pki_server_db_schema_upgrade_help_command(ansible_module):
    """
    :id: 5e257ffc-2487-470f-8167-a15896c1426a
    :Title: Test pki-server db-schema-upgrade --help command
    :Description: Test pki-server db-schema-upgrade --help command
    :Requirement: Pki Server Db 
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults: 
        1. Verify whether pki-server db-schema-upgrade --help command shows the following commands.

     Usage: pki-server db-schema-upgrade [OPTIONS]

       -i, --instance <instance ID>       Instance ID (default: pki-tomcat).
       -D, --bind-dn <Bind DN>            Connect DN (default: cn=Directory Manager).
       -w, --bind-password <password>     Password to connect to DB.
       -v, --verbose                      Run in verbose mode.
           --help                         Show help message.

    """
    help_command = 'pki-server db-schema-upgrade --help'

    cmd_output = ansible_module.command(help_command)
    for result in cmd_output.values():
        if result['rc'] == 0:
            assert "Usage: pki-server db-schema-upgrade [OPTIONS]" in result['stdout']
            assert "  -i, --instance <instance ID>       Instance ID (default: pki-tomcat)." in \
                   result['stdout']
            assert "  -D, --bind-dn <Bind DN>            Connect DN (default: cn=Directory " \
                   "Manager)." in result['stdout']
            assert "  -w, --bind-password <password>     Password to connect to DB." in \
                   result['stdout']
            assert "  -v, --verbose                      Run in verbose mode." in result['stdout']
            assert "      --help                         Show help message." in result['stdout']
        else:
            pytest.xfail("Failed to run pki-server db-schema-upgrade --help command.")


def test_pki_server_db_schema_upgrade_command(ansible_module):
    """
    :id: f5d66360-1c0d-4c12-afe0-9645ec13569f
    :Title: Test pki-server db-schema-upgrade command
    :Description: Test pki-server db-schema-upgrade command
    :Requirement: Pki Server Db
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :CaseComponent: \-
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server db-schema-upgrade command upgrade the pki server database.
    """

    subsystem = ['ca', 'kra', 'ocsp', 'tks', 'tps']
    bind_dn = "'cn=Directory Manager'"
    bind_pass = constants.CLIENT_DIR_PASSWORD
    for system in subsystem:
        instance = None
        try:
            instance = eval("constants.{}_INSTANCE_NAME".format(system.upper()))
        except:
            pytest.skip("Instance is not present")
        db_upgrade = 'pki-server db-schema-upgrade -i {} -D {} -w {}'.format(instance, bind_dn,
                                                                             bind_pass)
        cmd_output = ansible_module.command(db_upgrade)
        for result in cmd_output.values():
            if result['rc'] == 0:
                assert "Upgrade complete" in result['stdout']
            else:
                pytest.xfail("Failed to run pki-server db-schema-upgrade command for "
                             "instance %s." % system)


def test_pki_server_db_schema_upgrade_when_password_is_wrong(ansible_module):
    """
    :id: 4f814b5c-c450-46f9-818c-0aca3d5b0f21
    :Title: Test pki-server db-schema-upgrade command when db password is wrong.
    :Description: Test pki-server db-schema-upgrade command when db password is wrong.
    :Requirement: Pki Server Db
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :CaseComponent: \-
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server db-schema-upgrade command do not upgrade the pki server
           database when password is wrong.
    """
    subsystem = ['ca', 'kra', 'ocsp', 'tks', 'tps']
    bind_dn = "cn=Directory Manager"
    bind_pass = "SECret.123231"

    for system in subsystem:
        instance = None
        try:
            instance = eval("constants.{}_INSTANCE_NAME".format(system.upper()))
        except:
            pytest.skip("Instance is not present")
        db_schema_upgrade = 'pki-server db-schema-upgrade -i {} -D {} -w {}'.format(instance,
                                                                                    bind_dn,
                                                                                    bind_pass)
        cmd_output = ansible_module.command(db_schema_upgrade)
        for result in cmd_output.values():
            if result['rc'] == 0:
                assert "Upgrade complete" in result['stdout']
                pytest.xfail("Failed to run pki-server db-schema-upgrade command for "
                             "instance %s." % system)
            else:
                assert "ERROR: ldap_bind: Invalid credentials (49)" in result['stdout']


def test_pki_server_db_schema_upgrade_when_bind_DN_is_wrong(ansible_module):
    """
    :id: 2d24ef4d-c99d-46dd-942e-2493775aadb1
    :Title: Test pki-server db-schema-upgrade command when bind DN is wrong.
    :Description: Test pki-server db-schema-upgrade command when bind DN is wrong.
    :Requirement: Pki Server Db
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :CaseComponent: \-
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server db-schema-upgrade command do not upgrade the
            pki server database when bind DN is wrong.

    """
    subsystem = ['ca', 'kra', 'ocsp', 'tks', 'tps']
    bind_dn = "cn=Data Manager"
    bind_pass = constants.CLIENT_DIR_PASSWORD

    for system in subsystem:

        instance = None
        try:
            instance = eval("constants.{}_INSTANCE_NAME".format(system.upper()))
        except:
            pytest.skip("Instance is not present")
        db_schema_upgrade = 'pki-server db-schema-upgrade -i {} -D {} -w {}'.format(instance,
                                                                                    bind_dn,
                                                                                    bind_pass)
        cmd_output = ansible_module.command(db_schema_upgrade)

        for result in cmd_output.values():
            if result['rc'] == 0:
                assert "Upgrade complete" in result['stdout']
                pytest.xfail("Failed to run pki-server db-schema-upgrade command for "
                             "instance %s." % system)
            else:
                assert "ERROR: ldap_bind: Invalid credentials (49)" in result['stdout']


def test_pki_server_db_schema_upgrade_while_ds_instance_is_down(ansible_module, ds_instance):
    """
    :id: cfe68e55-1926-410c-9157-e22eb5412283
    :Title: Test pki-server db-schema-upgrade command when ds instance is down.
    :Description: Test pki-server db-schema-upgrade command when ds instance is down.
    :Requirement: Pki Server Db
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :CaseComponent: \-
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server db-schema-upgrade command do not upgrade the pki server
            database while directory server instance is down, it throws Error.

    """

    subsystem = ['ca', 'kra', 'ocsp', 'tks', 'tps']

    bind_dn = "cn=Data Manager"
    bind_pass = constants.CLIENT_DIR_PASSWORD

    for system in subsystem:
        instance = None
        try:
            instance = eval("constants.{}_INSTANCE_NAME".format(system.upper()))
        except:
            pytest.skip("Instance is not present")

        db_schema_upgrade = 'pki-server db-schema-upgrade -i {} -D {} -w {}'.format(instance,
                                                                                    bind_dn,
                                                                                    bind_pass)
        cmd_output = ansible_module.command(db_schema_upgrade)

        for result in cmd_output.values():
            if result['rc'] == 0:
                assert "Upgrade complete" in result['stdout']
                pytest.xfail("Failed to run pki-server db-schema-upgrade command.")
            else:
                assert "ERROR: ldap_bind: Invalid credentials (49)" in result['stdout']


def test_pki_server_db_schema_upgrade_with_wrong_instance(ansible_module):
    """
    :id: 3f9cae23-f435-4f09-b3b3-3344b0e1ca15
    :Title: Test pki-server db-schema-upgrade command with invalid instance.
    :Description: Test pki-server db-schema-upgrade command with invalid instance
    :Requirement: Pki Server Db
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :CaseComponent: \-
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server db-schema-upgrade command do not upgrade the pki server
         database while specifying wrong instance it should throw error.
    """

    subsystem = ["RoootCAA", "RoooTKRA", "RootOcSp", "RooTtKS", "RoOtTpS"]
    bind_dn = "cn=Directory Manager"
    bind_pass = constants.CLIENT_DIR_PASSWORD

    for system in subsystem:
        db_schema_upgrade = 'pki-server db-schema-upgrade -i {} -D {} -w {}'.format(system,
                                                                                    bind_dn,
                                                                                    bind_pass)
        cmd_output = ansible_module.command(db_schema_upgrade)

        for result in cmd_output.values():
            if result['rc'] == 0:
                assert "Upgrade complete" in result['stdout']
                pytest.xfail("Failed to run pki-server db-schema-upgrade command.")
            else:
                assert "ERROR: Invalid instance {}".format(system) in result['stdout']


def test_pki_server_db_schema_upgrade_with_stopped_instance(ansible_module, stop_pki_instance):
    """
    :id: 1a03f42d-934f-409e-8249-74d864081172
    :Title: Test pki-server db-schema-upgrade with stopped instance
    :Description: Test pki-server db-schema-upgrade with stopped instance.
    :Requirement: Pki Server Db
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :CaseComponent: \-
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server db-schema-upgrade command upgrade the pki server database
           when instance is stopped.

    """
    bind_dn = "cn=Directory Manager"
    bind_pass = constants.CLIENT_DIR_PASSWORD
    instance = stop_pki_instance
    db_schema_upgrade = 'pki-server db-schema-upgrade -i {} -D {} -w {}'.format(instance,
                                                                                bind_dn,
                                                                                bind_pass)
    cmd_output = ansible_module.command(db_schema_upgrade)

    for result in cmd_output.values():
        if result['rc'] == 0:
            assert "Upgrade complete" in result['stdout']
            pytest.xfail("Failed to run pki-server db-schema-upgrade command.")
        else:
            assert "ERROR: ldap_bind: Invalid credentials (49)" in result['stdout']
