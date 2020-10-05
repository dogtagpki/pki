"""
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Tests commands:
#                pki pkcs12-cert-export
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


def test_pki_pkcs12_cert_export_help(ansible_module):
    """
    :id: 62e4f26d-eda0-4015-a5e5-75a8b8ec6e89
    :Title: Test pki pkcs12-cert-export --help command
    :Description: test pki pkcs12-cert-export --help command
    :CaseComponent: \-
    :Requirement: Pki Pkcs12
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki pkcs12-cert-export --help
    :ExpectedResults:
        1. Verify whether pki pkcs12-cert-export --help command shows help options
    """

    add_out = ansible_module.command('pki pkcs12-cert-export --help')
    for result in add_out.values():
        if result['rc'] == 0:
            assert "usage: pkcs12-cert-export [OPTIONS...] [nickname]" in result['stdout']
            assert "--cert-file <path>              Certificate file" in result['stdout']
            assert "--cert-id <ID>                  Certificate ID to export" in result['stdout']
            assert "--debug                         Run in debug mode." in result['stdout']
            assert "--help                          Show help message." in result['stdout']
            assert "--pkcs12-file <path>            PKCS #12 file" in result['stdout']
            assert "--pkcs12-password <password>    PKCS #12 password" in result['stdout']
            assert "--pkcs12-password-file <path>   PKCS #12 password file" in result['stdout']
            assert "-v,--verbose                       Run in verbose mode." in result['stdout']
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail("Failed to run pki pkcs12-cert-export command.")


def test_pki_pkcs12_cert_export(ansible_module):
    """
    :id: 5f7e9912-b754-43db-98d8-71da4e7b1079
    :Title: Test pki pkcs12-cert-export without any cert-file option.
    :Description: Test pki pkcs12-cert-export without any cert-file option.
    :Requirement: Pki Pkcs12
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
            1. pki pkcs12-cert-add --pkcs12-file <p12_file> --pkcs12-password <password>
            2. pki pkcs12-cert-export --pkcs12-file <p12_file> --pkcs12-password <password>
    :Expectedresults:
            1. It should throw an error.
    """
    pkcs12_file = '{}/ca_cert.p12'.format(db2)

    for nick in [constants.CA_ADMIN_NICK, constants.KRA_ADMIN_NICK]:
        pkcs12_add = 'pki -d {} -c {} pkcs12-cert-add "{}" --pkcs12-file {} ' \
                     '--pkcs12-password {}'.format(db1, constants.CLIENT_DIR_PASSWORD, nick,
                                                   pkcs12_file, constants.CLIENT_DIR_PASSWORD)
        add_cert = ansible_module.command(pkcs12_add)
        for result in add_cert.values():
            if result['rc'] == 0:
                assert 'Added certificate "{}"'.format(nick) in result['stdout']

    pkcs12_export = 'pki -d {} -c {} pkcs12-cert-export "{}" ' \
                    '--pkcs12-file {} --pkcs12-password {} '.format(db1,
                                                                    constants.CLIENT_DIR_PASSWORD,
                                                                    constants.CA_ADMIN_NICK,
                                                                    pkcs12_file,
                                                                    constants.CLIENT_DIR_PASSWORD)

    export = ansible_module.command(pkcs12_export)
    for result in export.values():
        if result['rc'] == 0:
            pytest.fail("Failed to Export cert using pkcs12-export command.")
        else:
            assert "ERROR: Missing certificate file." in result['stderr']
    ansible_module.command('rm -rf {}/ca_cert.p12'.format(db2))


def test_pki_pkcs12_cert_export_with_cert_file(ansible_module):
    """
    :id: 6d01fbf0-6cf0-4e57-9d86-34f07002b4d0
    :Title: Test pki pkcs12-cert-export command with --cert-file
    :Description: test pki pkcs12-cert-export command with --cert-file
    :Requirement: Pki Pkcs12
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki pkcs12-cert-add --pkcs12-file <p12_file> --pkcs12-password <password>
        2. pki pkcs12-cert-export --pkcs12-file <p12_file> --pkcs12-password <password> --cert-file
    :ExpectedResults:
        1. Verify whether pki pkcs12-cert-export command exports the cert to pem file.
    """
    pkcs12_file = '{}/ca_cert.p12'.format(db2)
    pem_file = '/tmp/ca_admin_cert.pem'

    for nick in [constants.CA_ADMIN_NICK, constants.KRA_ADMIN_NICK]:
        pkcs12_add = 'pki -d {} -c {} pkcs12-cert-add "{}" --pkcs12-file {} ' \
                     '--pkcs12-password {}'.format(db1, constants.CLIENT_DIR_PASSWORD, nick,
                                                   pkcs12_file, constants.CLIENT_DIR_PASSWORD)
        add_cert = ansible_module.command(pkcs12_add)
        for result in add_cert.values():
            if result['rc'] == 0:
                assert 'Added certificate "{}"'.format(nick) in result['stdout']

    pkcs12_export = 'pki -d {} -c {} pkcs12-cert-export "{}" ' \
                    '--pkcs12-file {} --pkcs12-password {} ' \
                    '--cert-file {}'.format(db1, constants.CLIENT_DIR_PASSWORD,
                                            constants.CA_ADMIN_NICK, pkcs12_file,
                                            constants.CLIENT_DIR_PASSWORD, pem_file)

    export = ansible_module.command(pkcs12_export)
    for result in export.values():
        if result['rc'] == 0:
            is_file = ansible_module.stat(path=pem_file)
            for r in is_file.values():
                assert r['stat']['exists']
        else:
            pytest.fail("Failed to Export cert using pkcs12-export command..")
    cat_output = ansible_module.command('cat {}'.format(pem_file))
    for res in cat_output.values():
        if res['rc'] == 0:
            assert "-----BEGIN CERTIFICATE-----" in res['stdout']
            assert "-----END CERTIFICATE-----" in res['stdout']
    ansible_module.command('rm -rf {}/ca_cert.p12'.format(db2))


def test_pki_pkcs12_cert_export_cert_id(ansible_module):
    """
    :id: fda1a812-3538-416c-86b1-0733c32a01c4
    :Title: Test pki pkcs12-cert-export --cert-id command
    :Description: test pki pkcs12-cert-export --cert-id command
    :CaseComponent: \-
    :Requirement: Pki Pkcs12
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki pkcs12-cert-export --cert-id <cert_id> --pkcs12-file <p12_file>
        --pkcs12-password <password>
    :ExpectedResults:
        1. It should export the certificate with the cert id.
    """
    p12_file = '/tmp/ca_admin_cert.p12'
    pem_file = '/tmp/ca_admin_cert.pem'
    ansible_module.command('cp -R {}/ca_admin_cert.p12 /tmp/'.format(constants.CA_CLIENT_DIR))

    pkcs12_find = 'pki pkcs12-cert-find --pkcs12-file {} ' \
                  '--pkcs12-password {}'.format(p12_file, constants.CLIENT_DIR_PASSWORD)
    cert_find_out = ansible_module.command(pkcs12_find)
    for result in cert_find_out.values():
        if result['rc'] == 0:
            cert_id = re.search('Certificate ID: [\w]*', result['stdout'])
            c_id = cert_id.group().split(':')[1].strip()

            export = 'pki pkcs12-cert-export --pkcs12-file {} --pkcs12-password {} ' \
                     '--cert-file {} --cert-id {}'.format(p12_file, constants.CLIENT_DIR_PASSWORD,
                                                          pem_file, c_id)
            export_out = ansible_module.command(export)
            for res in export_out.values():
                if res['rc'] == 0:
                    is_file = ansible_module.stat(path=pem_file)
                    for r in is_file.values():
                        assert r['stat']['exists']
                        cat_output = ansible_module.command('cat {}'.format(pem_file))
                        for r1 in cat_output.values():
                            if r1['rc'] == 0:
                                assert "-----BEGIN CERTIFICATE-----" in r1['stdout']
                                assert "-----END CERTIFICATE-----" in r1['stdout']
                            else:
                                pytest.fail("Failed to run cat {}".format(pem_file))
                else:
                    log.error(res['stdout'])
                    log.error(res['stderr'])
                    pytest.fail("Failed to run pki pkcs12-cert-export command.")
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail("Failed to Export cert using pkcs12-export command..")
    ansible_module.command('rm -rf {} {}'.format(p12_file, pem_file))


def test_pki_pkcs12_cert_export_cert_id_junk(ansible_module):
    """
    :id: a7ffe7bd-6992-4e4c-b128-5c947c91edf0
    :Title: Test pki pkcs12-cert-export --cert-id with junk id.
    :Description: test pki pkcs12-cert-export --cert-id with junk text.
    :CaseComponent: \-
    :Requirement: Pki Pkcs12
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki pkcs12-cert-export --pkcs12-file <p12_file> --pkcs12-password <passowrd>
        --cert-id <invalid_cert_id>
    :ExpectedResults:
        1. It will throw an error certificate not found.
    """
    junk_id = ''.join(random.choice('0123456789abcdef') for _ in range(20))
    p12_file = '/tmp/ca_admin_cert.p12'
    pem_file = '/tmp/ca_admin_cert.pem'
    ansible_module.command('cp -R {}/ca_admin_cert.p12 /tmp/'.format(constants.CA_CLIENT_DIR))

    export = 'pki pkcs12-cert-export --pkcs12-file {} --pkcs12-password {} ' \
             '--cert-file {} --cert-id {}'.format(p12_file, constants.CLIENT_DIR_PASSWORD,
                                                  pem_file, junk_id)
    export_out = ansible_module.command(export)
    for result in export_out.values():
        if result['rc'] == 0:
            pytest.fail("Failed to export cert with random cert id.")
        else:
            assert "ERROR: Certificate not found." in result['stderr']
    ansible_module.command('rm -rf {} {}'.format(p12_file, pem_file))


def test_pki_pkcs12_cert_export_wrong_pkcs12_password(ansible_module):
    """
    :id: e64394ad-9e4f-4938-bedd-69b89026a8a3
    :Title: Test pki pkcs12-cert-export command with wrong pkcs12 password.
    :Description: test pki pkcs12-cert-export command with wrong pkcs12 password.
    :CaseComponent: \-
    :Requirement: Pki Pkcs12
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki pkcs12-cert-export --pkcs12-file <file> --pkcs12-password <wrong_password>
           --cert-id <cert_id>
    :ExpectedResults:
        1. Verify whether pki pkcs12-cert-export command with wrong pkcs12 password throws error.
    """
    wrong_password = ''.join(random.choice(string.ascii_uppercase +
                                           string.digits +
                                           string.ascii_letters +
                                           string.punctuation)
                             for _ in range(8))
    p12_file = '/tmp/ca_admin_cert.p12'
    pem_file = '/tmp/ca_admin_cert.pem'
    ansible_module.command('cp -R {}/ca_admin_cert.p12 /tmp/'.format(constants.CA_CLIENT_DIR))

    export = 'pki pkcs12-cert-export "{}" --pkcs12-file {} --pkcs12-password {} ' \
             '--cert-file {}'.format(constants.CA_ADMIN_NICK, p12_file,
                                     wrong_password, pem_file)
    export_out = ansible_module.command(export)
    for result in export_out.values():
        if result['rc'] > 0:
            assert "ERROR: Unable to validate PKCS #12 file: Digests do not match" in result['stderr']
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail("Failed: Ran pki pkcs12-cert-export command with wrong pkcs12 password.")

    ansible_module.command('rm -rf {} {}'.format(p12_file, pem_file))


def test_pki_pkcs12_cert_export_wrong_db_password(ansible_module):
    """
    :id: 5fc80f72-b8b0-49a7-b62d-807f4355b6d6
    :Title: Test pki pkcs12-cert-export command with db password
    :Description: test pki pkcs12-cert-export command with db password.
    :CaseComponent: \-
    :Requirement: Pki Pkcs12
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Setps:
        1. Export certs to file.
        2. pki -d <wrong_password> -d <database> pkcs12-cert-export --pkcs12-file <file>
        --pkcs12-password <password> --cert-file <file>
    :ExpectedResults:
        1. Verify whether pki pkcs12-cert-export command with wrong password db throws error.
    """
    wrong_password = ''.join(random.choice(string.ascii_uppercase +
                                           string.digits +
                                           string.ascii_letters +
                                           string.punctuation)
                             for _ in range(8))
    p12_file = '/tmp/ca_admin_cert.p12'
    pem_file = '/tmp/ca_admin_cert.pem'
    ansible_module.command('cp -R {}/ca_admin_cert.p12 /tmp/'.format(constants.CA_CLIENT_DIR))

    export = 'pki -d {} -c "{}" pkcs12-cert-export "{}" --pkcs12-file {} --pkcs12-password {} ' \
             '--cert-file {}'.format(db1, wrong_password, constants.CA_ADMIN_NICK, p12_file,
                                     constants.CLIENT_DIR_PASSWORD, pem_file)
    export_out = ansible_module.command(export)
    for result in export_out.values():
        if result['rc'] > 0:
            assert "ERROR: Incorrect password for internal token" in result['stderr']
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail("Failed: Ran pki pkcs12-cert-export command with wrong db password.")
    ansible_module.command('rm -rf {} {}'.format(p12_file, pem_file))


def test_pki_pkcs12_cert_export_verbose(ansible_module):
    """
    :id: c426d204-5ce3-42a1-b171-8bd82d2df4b6
    :Title: Test pki pkcs12-cert-export --verbose command.
    :Description: test pki pkcs12-cert-export command
    :Requirement: Pki Pkcs12
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki pkcs12-cert-export <cert_id> --pkcs12-file <file>
        --pkcs12-password <password> --verbose
    :ExpectedResults:
        1. Verify whether pki pkcs12-cert-export --verbose command show verbose output.
    """
    p12_file = '/tmp/ca_admin_cert.p12'
    pem_file = '/tmp/ca_admin_cert.pem'
    ansible_module.command('cp -R {}/ca_admin_cert.p12 /tmp/'.format(constants.CA_CLIENT_DIR))

    export = 'pki pkcs12-cert-export "{}" --pkcs12-file {} --pkcs12-password {} ' \
             '--cert-file {} --verbose'.format(constants.CA_ADMIN_NICK, p12_file,
                                               constants.CLIENT_DIR_PASSWORD, pem_file)
    export_out = ansible_module.command(export)
    for result in export_out.values():
        if result['rc'] == 0:
            is_file = ansible_module.stat(path=pem_file)
            for r in is_file.values():
                assert r['stat']['exists']
                cat_output = ansible_module.command('cat {}'.format(pem_file))
                for r1 in cat_output.values():
                    if r1['rc'] == 0:
                        assert "-----BEGIN CERTIFICATE-----" in r1['stdout']
                        assert "-----END CERTIFICATE-----" in r1['stdout']
        else:
            pytest.fail("Failed: Ran pki pkcs12-cert-export command with wrong db password..")
    ansible_module.command('rm -rf {} {}'.format(p12_file, pem_file))
