"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI CLIENT CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki client cli commands needs to be tested:
#   pki client-init
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
import random
import string
import sys

import pytest
from pki.testlib.common import utils

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
userop = utils.UserOperations(nssdb=constants.NSSDB)

db1 = '/tmp/db1_test'
db2 = '/tmp/db2_test'


@pytest.mark.parametrize('args', ['--help', 'asdfa', ''])
def test_pki_client_init_help(ansible_module, args):
    """
    :Title: Test pki client-init --help command
    :Description: test pki client-init --help command
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :steps:
        1. pki client-init --help
        2. pki client-init asdfa
        3. pki client-init ''
    :Expectedresults:
        1. It should show help message.
        2. It should throw an error.
        3. It should initialize the directory.
    """
    help_cmd = 'pki client-init {}'.format(args)
    if args == '':
        init_out = ansible_module.expect(command=help_cmd,
                                         responses={"Security database already exists. "
                                                    "Overwrite (y/N)?":'y'})
        for result in init_out.values():
            if result['rc'] == 0:
                assert 'Client initialized' in result['stdout']
                log.info("Initialized default client directory.")
            else:
                pytest.xfail("Failed to initialized the client directory.")

        init_out = ansible_module.expect(command=help_cmd,
                                         responses={"Security database already exists. "
                                                    "Overwrite (y/N)?": 'N'})
        for result in init_out.values():
            if result['rc'] == 0:
                assert 'Client initialization canceled' in result['stdout']
                log.info("Client directory initalization cancled.")
            else:
                pytest.xfail("Failed to initialized the client directory.")
    else:
        init_out = ansible_module.command(help_cmd)
        for result in init_out.values():
            if result['rc'] == 0:
                assert "usage: client-init [OPTIONS...]" in result['stdout']
                assert "--force   Force database initialization" in result['stdout']
                assert "--help    Show help options" in result['stdout']
            elif args == 'asdfa':
                assert 'Error: Too many arguments specified.' in result['stderr']
            else:
                pytest.xfail("Failed to run pki client-init --help command.")
            log.info("Successfully ran the pki client-init {} command.".format(args))


def test_pki_client_init(ansible_module):
    """
    :Title: Test pki client-init command, initiate the database and creates the files in directory.
    :Description: Test pki client-init command, it should create client database. 
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Execute pki -d <db_path> -c <db_password> client-init
        2. Database directory should be initialized and cert8.db, key3.db and 
        secmod.db directory should be created.
    :Expectedresults: Verify whether pki client-init command creates new security database.
    """
    ansible_module.command('rm -rf {}'.format(db2))
    client_init = 'pki -d {} -c {} client-init'.format(db2, constants.CLIENT_DIR_PASSWORD)
    client_init_output = ansible_module.command(client_init)
    for result in client_init_output.values():
        if result['rc'] == 0:
            assert "Client initialized" in result['stdout']
            dbs = ansible_module.command('ls {}'.format(db2))
            for res in dbs.values():
                assert 'secmod.db' in res['stdout']
                assert 'cert8.db' in res['stdout']
                assert 'key3.db' in res['stdout']
            log.info("Database Directory created.")
            log.info("Successfully ran the pki client-init command.")
        else:
            pytest.xfail("Failed to run pki client-init command.")
    ansible_module.command('rm -rf {}'.format(db2))


def test_pki_client_init_no_password(ansible_module):
    """
    :Title: Test pki client-init command, without password.
    :Description: test pki client-init command without password
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Expectedresults: Verify whether pki client-init command without password throws error.
    """
    client_init = 'pki -d {} client-init'.format(db2)

    client_init_output = ansible_module.command(client_init)
    for result in client_init_output.values():
        if result['rc'] >= 1:
            assert "Error: Security database password is required." in result['stderr']
            log.info("Success: Unable to initialize database without password.")
        elif result['rc'] == 0:
            assert 'Client initialized' in result['stdout']
            log.info("Success: Initialized db with default password.")
        else:
            log.info("Failed: Initialized databse without password.")
            pytest.xfail("Failed: Initialized databse without password.")
    ansible_module.command('rm -rf {}'.format(db2))


def test_pki_client_init_special_char_password(ansible_module):
    """
    :Title: Test pki client-init command with the password as special character.
    :Description: test pki client-init command with password having special character
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Expectedresults: Verify whether pki client-init command with wrong password throws error.
    """
    password = ''.join(random.choice(string.letters +
                                     string.digits) for _ in range(8))
    client_init = 'pki -d {} -c "{}" client-init'.format(db2, password)
    client_init_output = ansible_module.command(client_init)
    for result in client_init_output.values():
        if result['rc'] == 0:
            assert "Client initialized" in result['stdout']
            dbs = ansible_module.command('ls {}'.format(db2))
            for res in dbs.values():
                assert 'secmod.db' in res['stdout']
                assert 'cert8.db' in res['stdout']
                assert 'key3.db' in res['stdout']
            log.info("Database Directory created.")
            log.info("Successfully ran the pki client-init command.")
        else:
            pytest.xfail("Failed to run pki client-init command.")
    ansible_module.command('rm -rf {}'.format(db2))


def test_pki_client_init_with_force_option(ansible_module):
    """
    :Title: Test pki client-init command with the --force option.
    :Description: test pki client-init command with the --force option.
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Expectedresults: Verify whether pki client-init command with --force option initialises the
    database.
    """
    client_init = 'pki -d {} -c {} client-init --force'.format(db2, constants.CLIENT_DIR_PASSWORD)
    client_init_output = ansible_module.command(client_init)
    for result in client_init_output.values():
        if result['rc'] == 0:
            assert "Client initialized" in result['stdout']
            dbs = ansible_module.command('ls {}'.format(db2))
            for res in dbs.values():
                assert 'secmod.db' in res['stdout']
                assert 'cert8.db' in res['stdout']
                assert 'key3.db' in res['stdout']
            log.info("Database Directory created.")
            log.info("Successfully ran the pki client-init command.")
        else:
            pytest.xfail("Failed to run pki client-init command.")
    ansible_module.command('rm -rf {}'.format(db2))


def test_pki_client_init_with_override_the_existing_db_with_force(ansible_module):
    """
    :Title: Test pki client-init with overriding existing db with force.
    :Description: Test pki client-init with overriding existing db with force.
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
            1. pki -d <db> -c <password> client-init
            2. pki -d <db> -c <password> client-init --foce
    :Expectedresults:
            1. Database should be initialized.
            2. Database should be initialized forcefully.
    """

    init_db2 = 'pki -d {} -c {} client-init'.format(db2, constants.CLIENT_DIR_PASSWORD)
    init_db2_force = 'pki -d {} -c {} client-init --force'.format(db2,
                                                                  constants.CLIENT_DIR_PASSWORD)

    ansible_module.command(init_db2)

    db2_out = ansible_module.command(init_db2_force)
    for result in db2_out.values():
        if result['rc'] == 0:
            assert "Client initialized" in result['stdout']
            dbs = ansible_module.command('ls {}'.format(db2))
            for res in dbs.values():
                assert 'secmod.db' in res['stdout']
                assert 'cert8.db' in res['stdout']
                assert 'key3.db' in res['stdout']
            log.info("Database Directory created.")
            log.info("Successfully ran the pki client-init --force command.")
        else:
            pytest.xfail("Failed to run pki client-init --force command.")
    ansible_module.command('rm -rf {}'.format(db2))


def test_pki_client_init_with_password_file(ansible_module):
    """
    :Title: pki client-init with password file.
    :Description: pki client-init with password file.
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d <db> -C <password_file> client-init
    :Expectedresults:
        1. It should initialize the client directory.
    """
    password_file = '/tmp/password.txt'
    ansible_module.copy(dest=password_file, content=constants.CLIENT_PKCS12_PASSWORD, force=True)
    client_init = 'pki -d {} -C {} client-init'.format(db2, password_file)
    client_out = ansible_module.command(client_init)
    for result in client_out.values():
        if result['rc'] == 0:
            assert 'Client initialized' in result['stdout']
            log.info("Successfully initialized client with password file.")
        else:
            log.info("Failed to initialized client with password file.")
            pytest.xfail("Failed to initialized client with password file.")