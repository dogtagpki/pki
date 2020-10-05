"""
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 #
 #   Description: Tests following command:
 #                pki pkcs12-key-del
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
import random
import re
import string
import sys

import pytest

from pki.testlib.common.utils import get_random_string

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

db1 = '/tmp/db1_test'
db2 = '/tmp/db2_test'

TOPOLOGY = constants.CA_INSTANCE_NAME.split("-")[-2]

if TOPOLOGY == '01':
    instance_name = 'pki-tomcat'
    topology_name = 'topology-01-CA'
else:
    instance_name = constants.CA_INSTANCE_NAME
    topology_name = constants.CA_INSTANCE_NAME


@pytest.mark.ansible_playbook_setup('init_dir.yaml')
@pytest.mark.setup
def test_setup(ansible_playbook):
    pass


@pytest.fixture(autouse=True)
def init_db2(ansible_module):
    ansible_module.command('pki -d {} -c {} client-init '
                           '--force'.format(db2, constants.CLIENT_DIR_PASSWORD))


def test_pki_pkcs12_key_del_help(ansible_module):
    """
    :id: 2fef1223-3c14-4803-b82d-2311baa8a64b
    :Title: Test pki pkcs12-key-del --help command
    :Description: test pki pkcs12-key-del --help command
    :CaseComponent: \-
    :Requirement: Pki Pkcs12
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki pkcs12-key-del --help
    :ExpectedResults:
        1. Verify whether pki pkcs12-key-del --help command shows help options
    """

    key_out = ansible_module.command('pki pkcs12-key-del --help')
    for result in key_out.values():
        if result['rc'] == 0:
            assert "--debug                         Run in debug mode" in result['stdout']
            assert "--help                          Show help message." in result['stdout']
            assert "--pkcs12-file <path>            PKCS #12 file" in result['stdout']
            assert "--pkcs12-password <password>    PKCS #12 password" in result['stdout']
            assert "--pkcs12-password-file <path>   PKCS #12 password file" in result['stdout']
            assert "-v,--verbose                       Run in verbose mode." in result['stdout']
        else:
            pytest.fail("Failed to run pki pkcs12-key-del command.")


def test_pki_pkcs12_key_del(ansible_module):
    """
    :id: 054991d2-3de0-4e1b-a6cb-f2860111480b
    :Title: Test pki pkcs12-key-del command
    :Description: test pki pkcs12-key-del command
    :CaseComponent: \-
    :Requirement: Pki Pkcs12
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Pki pkcs12-key-del --pkcs12-file <file> --pkcs12-password <password>
    :ExpectedResults:
        1. Verify whether pki pkcs12-key-del command deletes the key.
    """
    p12_file = '/tmp/all_certs.p12'
    keys = []
    pki_server_subsystem = 'pki-server subsystem-cert-export -i {} --pkcs12-file {} ' \
                           '--pkcs12-password {} ca'.format(instance_name, p12_file,
                                                            constants.CLIENT_PKCS12_PASSWORD)
    key_find = 'pki pkcs12-key-find --pkcs12-file {} ' \
               '--pkcs12-password {}'.format(p12_file, constants.CLIENT_PKCS12_PASSWORD)
    key_del = 'pki pkcs12-key-del "{}" --pkcs12-file {} --pkcs12-password {}'
    ansible_module.command(pki_server_subsystem)
    find_keys = ansible_module.command(key_find)
    for result in find_keys.values():
        if result['rc'] == 0:
            raw_keys = re.findall('Key ID: [\w].*', result['stdout'])
            keys = [i.split(":")[1].strip() for i in raw_keys]

    for key in keys:
        key_del_out = ansible_module.command(
            key_del.format(key, p12_file, constants.CLIENT_PKCS12_PASSWORD))
        for result in key_del_out.values():
            if result['rc'] == 0:
                assert 'Deleted key "{}"'.format(key) in result['stdout']
            else:
                pytest.fail("Failed to run pki pkcs12-key-del command.")

    key_find_out = ansible_module.command(key_find)
    for res in key_find_out.values():
        if res['rc'] == 0:
            for key in keys:
                assert key not in res['stdout']
        else:
            pytest.fail("Failed to run pki pkcs12-key-find command.")
    ansible_module.command('rm -rf {}'.format(p12_file))


def test_pki_pkcs12_key_del_password_file(ansible_module):
    """
    :id: 9f0d997c-106b-4b28-aef3-ec8febf95078
    :Title: Test pki pkcs12-key-del with --pkcs12-password-file option
    :Description: test pki pkcs12-key-del command with password file
    :CaseComponent: \-
    :Requirement: Pki Pkcs12
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki pkcs12-key-del --pkcs12-file <p12_file> --pkcs12-password-file <password_file>
    :ExpectedResults:
        1. Verify whether pki pkcs12-key-del command deletes the key.
    """
    p12_file = '/tmp/all_certs.p12'
    password_file = '/tmp/password.txt'
    ansible_module.copy(content=constants.CLIENT_PKCS12_PASSWORD,
                        dest=password_file,
                        force=True)
    keys = []
    pki_server_subsystem = 'pki-server subsystem-cert-export -i {} --pkcs12-file {} ' \
                           '--pkcs12-password {} ca'.format(instance_name, p12_file,
                                                            constants.CLIENT_PKCS12_PASSWORD)
    key_find = 'pki pkcs12-key-find --pkcs12-file {} ' \
               '--pkcs12-password {}'.format(p12_file, constants.CLIENT_PKCS12_PASSWORD)
    key_del = 'pki pkcs12-key-del "{}" --pkcs12-file {} --pkcs12-password-file {}'
    # certutil = 'certutil -L -d {}'.format(db2)
    ansible_module.command(pki_server_subsystem)
    find_keys = ansible_module.command(key_find)
    for result in find_keys.values():
        if result['rc'] == 0:
            raw_keys = re.findall('Key ID: [\w].*', result['stdout'])
            keys = [i.split(":")[1].strip() for i in raw_keys]

    for key in keys:
        key_del_out = ansible_module.command(key_del.format(key, p12_file, password_file))
        for result in key_del_out.values():
            if result['rc'] == 0:
                assert 'Deleted key "{}"'.format(key) in result['stdout']
            else:
                pytest.fail("Failed to run pki pkcs12-key-del command.")

    key_find_out = ansible_module.command(key_find)
    for res in key_find_out.values():
        if res['rc'] == 0:
            for key in keys:
                assert key not in res['stdout']
        else:
            pytest.fail("Failed to run pki pkcs12-key-find command.")
    ansible_module.command('rm -rf {} {}'.format(p12_file, password_file))


def test_pki_pkcs12_key_del_wrong_pkcs12_password(ansible_module):
    """
    :id: f297012c-3fc8-48e0-acdd-162b29321cb6
    :Title: Test pki pkcs12-key-del command with wrong pkcs12 password
    :Description: test pki pkcs12-key-del command with wrong pkcs12 password.
    :CaseComponent: \-
    :Requirement: Pki Pkcs12
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki pkcs12-key-del --pkcs12-file <file> --pkcs12-password <invalid_pass>
    :ExpectedResults:
        Verify whether pki pkcs12-key-del command with wrong password throws error.
    """
    wrong_password = get_random_string(len=10)
    p12_file = '/tmp/all_certs.p12'
    keys = []
    pki_server_subsystem = 'pki-server subsystem-cert-export -i {} --pkcs12-file {} ' \
                           '--pkcs12-password {} ca'.format(instance_name, p12_file, constants.CLIENT_PKCS12_PASSWORD)
    key_find = 'pki pkcs12-key-find --pkcs12-file {} ' \
               '--pkcs12-password {}'.format(p12_file, constants.CLIENT_PKCS12_PASSWORD)
    key_del = 'pki pkcs12-key-del "{}" --pkcs12-file {} --pkcs12-password {}'
    ansible_module.command(pki_server_subsystem)
    find_keys = ansible_module.command(key_find)
    for result in find_keys.values():
        if result['rc'] == 0:
            raw_keys = re.findall('Key ID: [\w].*', result['stdout'])
            keys = [i.split(":")[1].strip() for i in raw_keys]

    for key in keys:
        key_del_out = ansible_module.command(key_del.format(key, p12_file, wrong_password))
        for result in key_del_out.values():
            if result['rc'] >= 1:
                assert "ERROR: Unable to validate PKCS #12 file: Digests do not match" in \
                       result['stderr']
            else:
                pytest.fail("Failed to run pki pkcs12-key-del command.")
    ansible_module.command('rm -rf {}'.format(p12_file))


def test_pki_pkcs12_key_del_wrong_db_password(ansible_module):
    """
    :id: f297012c-3fc8-48e0-acdd-162b29321cb6
    :Title: Test pki pkcs12-key-del command with wrong pkcs12 password
    :Description: test pki pkcs12-key-del command with wrong pkcs12 password.
    :CaseComponent: \-
    :Requirement: Pki Pkcs12
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d <db> -c <pass> pkcs12-key-del --pkcs12-file <file> --pkcs12-password <password>
    :ExpectedResults:
        Verify whether pki pkcs12-key-del command with wrong password throws error.
    """
    wrong_password = get_random_string(len=10)
    p12_file = '/tmp/all_certs.p12'
    keys = []
    pki_server_subsystem = 'pki-server subsystem-cert-export -i {} --pkcs12-file {} ' \
                           '--pkcs12-password {} ca'.format(instance_name, p12_file,
                                                            constants.CLIENT_PKCS12_PASSWORD)
    key_find = 'pki pkcs12-key-find --pkcs12-file {} ' \
               '--pkcs12-password {}'.format(p12_file, constants.CLIENT_PKCS12_PASSWORD)
    key_del = 'pki -d {} -c {} pkcs12-key-del "{}" --pkcs12-file {} --pkcs12-password {}'
    ansible_module.command(pki_server_subsystem)
    find_keys = ansible_module.command(key_find)
    for result in find_keys.values():
        if result['rc'] == 0:
            raw_keys = re.findall('Key ID: [\w].*', result['stdout'])
            keys = [i.split(":")[1].strip() for i in raw_keys]

    for key in keys:
        key_del_out = ansible_module.command(key_del.format(db2, wrong_password, key, p12_file,
                                                            wrong_password))
        for result in key_del_out.values():
            if result['rc'] >= 1:
                assert "ERROR: Incorrect password for internal token" in result['stderr']
            else:
                pytest.fail("Failed to run pki pkcs12-key-del command.")
    ansible_module.command('rm -rf {}'.format(p12_file))
