"""
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 #
 #   Description: Tests commands:
 #                pki pkcs12-cert
 #                pki pkcs12-cert-find
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
import string
import sys
import logging
import pytest

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants
log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)


def get_random_string(len=10):
    random_string = ''.join(random.choice(string.ascii_uppercase +
                                          string.digits +
                                          string.ascii_letters +
                                          string.punctuation)
                            for _ in range(len))
    return random_string


db1 = '/tmp/db1_test'
db2 = '/tmp/db2_test'


@pytest.mark.ansible_playbook_setup('init_dir.yaml')
@pytest.mark.setup
def test_setup(ansible_playbook):
    pass


@pytest.fixture(autouse=True)
def init_db2(ansible_module):
    ansible_module.command('pki -d {} -c {} client-init '
                           '--force'.format(db2, constants.CLIENT_DIR_PASSWORD))


def test_pki_pkcs12_cert(ansible_module):
    """
    :id: b7b35fe7-ebb6-498e-8caf-1dbc7698d7ea
    :Title: Test pki pkcs12-cert command.
    :Description: test pki pkcs12-cert command
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :CaseComponent: \-
    :Requirement: Pki Pkcs12
    :steps:
        1. pki pkcs12-cert --help
    :ExpectedResults:
        1. Verify whether pki pkcs12-cert command shows follwing output
            Commands:
             pkcs12-cert-add         Add certificate into PKCS #12 file
             pkcs12-cert-export      Export certificate from PKCS #12 file
             pkcs12-cert-find        Find certificates in PKCS #12 file
             pkcs12-cert-del         Remove certificate from PKCS #12 file
    """

    cert_out = ansible_module.command('pki pkcs12-cert')
    for result in cert_out.values():
        if result['rc'] == 0:
            assert "pkcs12-cert-add" in result['stdout']
            assert "pkcs12-cert-export" in result['stdout']
            assert "pkcs12-cert-find" in result['stdout']
            assert "pkcs12-cert-del" in result['stdout']
            assert "pkcs12-cert-import" in result['stdout']
            assert "pkcs12-cert-mod" in result['stdout']
        else:
            pytest.fail("Failed to run pki pkcs12-cert command.")


def test_pki_pkcs12_cert_find_help(ansible_module):
    """
    :id: 36e2b46b-186b-45fd-b9a9-99e9b227dfbe
    :Title: Test pki pkcs12-cert-find --help command.
    :Description: test pki pkcs12-cert-find --help command
    :Requirement: Pki Pkcs12
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki pkcs12-cert-find --help
    :ExpectedResults:
        1. Verify whether pki pkcs12-cert-find --help command shows help options
    """

    find_out = ansible_module.command('pki pkcs12-cert-find --help')
    for result in find_out.values():
        if result['rc'] == 0:
            assert "usage: pkcs12-cert-find [OPTIONS...]" in result['stdout']
            assert "--debug                         Run in debug mode." in result['stdout']
            assert "--help                          Show help message." in result['stdout']
            assert "-v,--verbose                       Run in verbose mode." in result['stdout']
        else:
            pytest.fail("Failed to run pki pkcs12-cert-find command.")


def test_pki_pkcs12_cert_find(ansible_module):
    """
    :id: 4e0ba258-06cc-4a8f-a323-84d6a23a0e25
    :Title: Test pki pkcs12-cert-find command.
    :Description: test pki pkcs12-cert-find command
    :Requirement: Pki Pkcs12
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki pkcs12-cert-find --pkcs12-file <file> --pkcs12-password <password>
    :ExpectedResults:
        1. It should lists the certs.
    """
    p12_file = '/tmp/all_certs.p12'
    export_cert = 'pki -d {} -c {} pkcs12-export  --pkcs12-file {} ' \
                  '--pkcs12-password {}'.format(db1, constants.CLIENT_DIR_PASSWORD,
                                                p12_file,
                                                constants.CLIENT_PKCS12_PASSWORD)
    ansible_module.command(export_cert)
    find_cmd = 'pki pkcs12-cert-find --pkcs12-file {} ' \
               '--pkcs12-password {}'.format(p12_file, constants.CLIENT_DIR_PASSWORD)
    find_out = ansible_module.command(find_cmd)
    for result in find_out.values():
        if result['rc'] == 0:
            assert "entries found" in result['stdout']
            assert "Certificate ID:" in result['stdout']
            assert "Serial Number:" in result['stdout']
            assert "Friendly Name: " in result['stdout']
            assert "Subject DN:" in result['stdout']
            assert "Issuer DN:" in result['stdout']
            assert "Trust Flags:" in result['stdout']
            assert "Has Key:" in result['stdout']
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail("Failed to run pki pkcs12-cert-find command.")


def test_pki_pkcs12_cert_find_password_file(ansible_module):
    """
    :id: 25ba454c-3ef3-4074-8284-223921bcc883
    :Title: Test pki pkcs12-cert-find with --pkcs12-password-file option
    :Description: test pki pkcs12-cert-find with --pkcs12-password-file option
    :Requirement: Pki Pkcs12
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki pkcs12-cert-find --pkcs12-file <file> --pkcs12-password-file <password_file>
    :ExpectedResults:
        1. Command should lists the certs with password-file option.
    """
    password_file = '/tmp/password.txt'
    p12_file = '/tmp/all_certs.p12'
    export_cert = 'pki -d {} -c {} pkcs12-export  --pkcs12-file {} ' \
                  '--pkcs12-password {}'.format(db1, constants.CLIENT_DIR_PASSWORD,
                                                p12_file,
                                                constants.CLIENT_PKCS12_PASSWORD)
    ansible_module.command(export_cert)
    ansible_module.shell('echo "{}" > {}'.format(constants.CLIENT_PKCS12_PASSWORD, password_file))
    find_cmd = 'pki pkcs12-cert-find --pkcs12-file {} ' \
               '--pkcs12-password-file {}'.format(p12_file, password_file)
    find_out = ansible_module.command(find_cmd)
    for result in find_out.values():
        if result['rc'] == 0:
            assert "entries found" in result['stdout']
            assert "Certificate ID:" in result['stdout']
            assert "Serial Number:" in result['stdout']
            assert "Friendly Name: " in result['stdout']
            assert "Subject DN:" in result['stdout']
            assert "Issuer DN:" in result['stdout']
            assert "Trust Flags:" in result['stdout']
            assert "Has Key:" in result['stdout']
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail("Failed to run pki pkcs12-cert-find command.")
    ansible_module.command('rm -rf {} {}'.format(p12_file, password_file))


def test_pki_pkcs12_cert_find_wrong_pkcs_password(ansible_module):
    """
    :id: ac1a0db6-c2af-4462-b7a9-7e80e976bae6
    :Title: Test pki pkcs12-cert-find command with wrong pkcs12 password
    :Description: test pki pkcs12-cert-find command with wrong pkcs12 password.
    :CaseComponent: \-
    :Requirement: Pki Pkcs12
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki pkcs12-cert-find --pkcs12-file <file> --pkcs12-password <worng password>
    :ExpectedResults:
        1. It should throw error with wrong pkcs password.
    """
    wrong_password = get_random_string(len=8)
    p12_file = '/tmp/all_certs.p12'
    export_cert = 'pki -d {} -c {} pkcs12-export  --pkcs12-file {} ' \
                  '--pkcs12-password {}'.format(db1, constants.CLIENT_DIR_PASSWORD,
                                                p12_file,
                                                constants.CLIENT_PKCS12_PASSWORD)
    ansible_module.command(export_cert)
    find_cmd = 'pki pkcs12-cert-find --pkcs12-file {} --pkcs12-password "{}"'.format(p12_file, wrong_password)
    find_out = ansible_module.command(find_cmd)
    for result in find_out.values():
        if result['rc'] > 0:
            assert "ERROR: Unable to validate PKCS #12 file: Digests do not match" in result['stderr']
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail("Failed: Ran pki pkcs12-cert-find command with wrong pkcs password.")


def test_pki_pkcs12_cert_find_wrong_db_password(ansible_module):
    """
    :id: da5553ef-2e28-4ce0-8787-4e3e011ccafb
    :Title: Test pki pkcs12-cert-find command with wrong db password.
    :Description: test pki pkcs12-cert-find command with wrong db password.
    :Requirement: Pki Pkcs12
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d <db> -c <wrong_pass> pkcs12-cert-find --pkcs12-file <file>
        --pkcs12-passowrd <password>
    :ExpectedResults:
        1. It should throw an error with wrong db password.
    """
    wrong_password = get_random_string(len=8)
    p12_file = '/tmp/all_certs.p12'
    export_cert = 'pki -d {} -c {} pkcs12-export  --pkcs12-file {} ' \
                  '--pkcs12-password {}'.format(db1, constants.CLIENT_DIR_PASSWORD,
                                                p12_file,
                                                constants.CLIENT_PKCS12_PASSWORD)
    ansible_module.command(export_cert)
    find_cmd = 'pki -d {} -c {} pkcs12-cert-find --pkcs12-file {} ' \
               '--pkcs12-password {}'.format(db1, wrong_password, p12_file,
                                             constants.CLIENT_PKCS12_PASSWORD)
    find_out = ansible_module.command(find_cmd)
    for result in find_out.values():
        if result['rc'] > 0:
            assert "ERROR: Incorrect password for internal token" in result['stderr']
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail("Failed: Ran pki pkcs12-cert-find command with wrong db password.")


def test_pki_pkcs12_cert_find_with_verbose_mode(ansible_module):
    """
    :id: 37c93d0f-2d0b-4c58-ac6f-a9607f722b49
    :Title: Test pki pkcs12-cert-find with verbose mode.
    :Description: Test pki pkcs12-cert-find with verbose mode.
    :Requirement: Pki Pkcs12
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki pkcs12-cert-find --pkcs12-file <file> --pkcs12-password <pass> -v
    :Expectedresults:
        1. It should show pki pkcs12-cert-find command.
    """
    p12_file = '/tmp/all_certs.p12'
    export_cert = 'pki -d {} -c {} pkcs12-export  --pkcs12-file {} ' \
                  '--pkcs12-password {}'.format(db1, constants.CLIENT_DIR_PASSWORD,
                                                p12_file,
                                                constants.CLIENT_PKCS12_PASSWORD)
    ansible_module.command(export_cert)
    find_cmd = 'pki pkcs12-cert-find --pkcs12-file {} ' \
               '--pkcs12-password {} -v'.format(p12_file, constants.CLIENT_PKCS12_PASSWORD)

    find_out = ansible_module.command(find_cmd)
    for result in find_out.values():
        if result['rc'] == 0:
            assert "Certificate ID:" in result['stdout']
            assert "Serial Number:" in result['stdout']
            assert "Friendly Name: " in result['stdout']
            assert "Subject DN:" in result['stdout']
            assert "Issuer DN:" in result['stdout']
            assert "Trust Flags:" in result['stdout']
            assert "Has Key:" in result['stdout']
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail("Failed to run pki pkcs12-cert-find with verbose mode.")
    ansible_module.command('rm -rf {}'.format(p12_file))
