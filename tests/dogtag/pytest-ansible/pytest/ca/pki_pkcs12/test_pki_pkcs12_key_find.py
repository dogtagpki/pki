"""
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Tests following command:
#                pki pkcs12-key
#                pki pkcs12-key-find
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
import re
import logging
import sys

import pytest

from pki.testlib.common.utils import get_random_string
log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
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


def test_pki_pkcs12_key(ansible_module):
    """
    :id: c3945363-e368-45fe-838a-5d1d23dc9cde
    :Title: Test pki pkcs12-key command
    :Description: test pki pkcs12-key command
    :CaseComponent: \-
    :Requirement: Pki Pkcs12
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki pkcs12-key
    :ExpectedResults:
         Verify whether pki pkcs12-key command shows following output
    Commands:
    pkcs12-key-find         Find keys in PKCS #12 file
    pkcs12-key-del          Remove key from PKCS #12 file
    """

    key_out = ansible_module.command('pki pkcs12-key')
    for result in key_out.values():
        if result['rc'] == 0:
            assert "pkcs12-key-find" in result['stdout']
            assert "pkcs12-key-del" in result['stdout']
        else:
            pytest.fail("Failed to run pki pkcs12-key command.!!")


def test_pki_pkcs12_key_find_help(ansible_module):
    """
    :id: 360a05da-78da-4dd2-92b8-9202d0c7cb37
    :Title: Test pki pkcs12-key-find --help command
    :Description: test pki pkcs12-key-find --help command
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :CaseComponent: \-
    :Requirement: Pki Pkcs12
    :Steps:
        1. pki pkcs12-key-find --help
    :ExpectedResults:
        1. Verify whether pki pkcs12-key-find --help command shows help options
    """
    key_out = ansible_module.command('pki pkcs12-key-find --help')
    for result in key_out.values():
        if result['rc'] == 0:
            assert "usage: pkcs12-key-find [OPTIONS...]" in result['stdout']
            assert "--debug                         Run in debug mode" in result['stdout']
            assert "--help                          Show help message." in result['stdout']
            assert "--pkcs12-file <path>            PKCS #12 file" in result['stdout']
            assert "--pkcs12-password <password>    PKCS #12 password" in result['stdout']
            assert "--pkcs12-password-file <path>   PKCS #12 password file" in result['stdout']
            assert "-v,--verbose                       Run in verbose mode." in result['stdout']
        else:
            pytest.fail("Failed to run pki pkcs12-key-find command.!!")


def test_pki_pkcs12_key_find_found(ansible_module):
    """
    :id: 94648a86-5a5f-42f8-ae16-e250276fd7ab
    :Title: Test pki pkcs12-key-find command
    :Description: test pki pkcs12-key-find command
    :CaseComponent: \-
    :Requirement: Pki Pkcs12
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki pkcs12-key-find --pkcs12-file <file> --pkcs12-password <password>
    :ExpectedResults:
         Verify whether pki pkcs12-key-find command lists the key(s).
    """
    p12_file = '/tmp/all_certs.p12'
    pki_server_subsystem = 'pki-server subsystem-cert-export -i {} --pkcs12-file {} ' \
                           '--pkcs12-password {} ca'.format(instance_name, p12_file,
                                                            constants.CLIENT_PKCS12_PASSWORD)
    key_find = 'pki pkcs12-key-find --pkcs12-file {} --pkcs12-password {}'
    ansible_module.command(pki_server_subsystem)

    key_find_out = ansible_module.command(key_find.format(p12_file,
                                                          constants.CLIENT_PKCS12_PASSWORD))
    for result in key_find_out.values():
        if result['rc'] == 0:
            assert "entries found" in result['stdout']
            assert "Key ID:" in result['stdout']
            assert "Friendly Name:" in result['stdout']
        else:
            pytest.fail("Failed to run pki pkcs12-key-find command.")
    ansible_module.command('rm -rf {}'.format(p12_file))


def test_pki_pkcs12_key_find_notfound(ansible_module):
    """
    :id: f52d92da-520a-460e-97a1-77c0c2dbf88c
    :Title: Test pki pkcs12-key-find command when no keys are present
    :Description: test pki pkcs12-key-find command when no keys are present
    :CaseComponent: \-
    :Requirement: Pki Pkcs12
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Pki pkcs12-key-find when keys are not present.
    :ExpectedResults:
        1. Verify whether pki pkcs12-key-find command lists the 0 key(s) for cert that does
        not has a key.
    """
    keys = []
    p12_file = '/tmp/all_certs.p12'
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
        key_del_out = ansible_module.command(key_del.format(key, p12_file,
                                                            constants.CLIENT_PKCS12_PASSWORD))
        for result in key_del_out.values():
            if result['rc'] == 0:
                assert 'Deleted key "{}"'.format(key) in result['stdout']
            else:
                pytest.fail("Failed to run pki pkcs12-key-del command.")

    key_out = ansible_module.command(key_find)
    for result in key_out.values():
        if result['rc'] == 0:
            assert "0 entries found" in result['stdout']
        else:
            pytest.fail("Failed to run pki pkcs12-key-find command.")
    ansible_module.command('rm -rf {}'.format(p12_file))


def test_pki_pkcs12_key_find_wrong_pkcs12_password(ansible_module):
    """
    :id: 89ec78fd-d686-407b-8e44-52ae1b3ac04a
    :Title: Test pki pkcs12-key-find command with wrong pkcs12 password
    :Description: test pki pkcs12-key-find command with wrong pkcs12 password.
    :CaseComponent: \-
    :Requirement: Pki Pkcs12
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki pkcs12-key-find --pkcs12-file --pkcs12-password <invalid_password>
    :ExpectedResults:
         Verify whether pki pkcs12-key-find command with wrong password throws error.
    """
    wrong_password = get_random_string(len=10)
    p12_file = '/tmp/all_certs.p12'
    pki_server_subsystem = 'pki-server subsystem-cert-export -i {} --pkcs12-file {} ' \
                           '--pkcs12-password {} ca'.format(instance_name, p12_file,
                                                            constants.CLIENT_PKCS12_PASSWORD)
    key_find = 'pki pkcs12-key-find --pkcs12-file {} ' \
               '--pkcs12-password "{}"'.format(p12_file, wrong_password)
    ansible_module.command(pki_server_subsystem)

    key_out = ansible_module.command(key_find)
    for result in key_out.values():
        if result['rc'] >= 0:
            assert "ERROR: Unable to validate PKCS #12 file: Digests do not match" in result['stderr']
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail("Failed to run pki pkcs12-key-find command.")


def test_pki_pkcs12_key_find_wrong_db_password(ansible_module):
    """
    :id: 1e6dc443-c764-47bc-81a9-ea58a10da9af
    :Title: Test pki pkcs12-key-find command with wrong db password.
    :Description: test pki pkcs12-key-find command with wrong db password.
    :Requirement: Pki Pkcs12
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Run pkcs12-key-find with wrong db password.
    :ExpectedResults:
         Verify whether pki pkcs12-key-find command with wrong password throws error.
    """
    wrong_password = get_random_string(len=10)

    p12_file = '/tmp/all_certs.p12'
    pki_server_subsystem = 'pki-server subsystem-cert-export -i {} --pkcs12-file {} ' \
                           '--pkcs12-password {} ca'.format(instance_name, p12_file,
                                                            constants.CLIENT_PKCS12_PASSWORD)
    key_find = 'pki pkcs12-key-find --pkcs12-file {} ' \
               '--pkcs12-password "{}"'.format(p12_file, wrong_password)
    ansible_module.command(pki_server_subsystem)

    key_out = ansible_module.command(key_find)
    for result in key_out.values():
        if result['rc'] > 0:
            assert "ERROR: Unable to validate PKCS #12 file: Digests do not match" in result['stderr']
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail("Failed to run pki pkcs12-key-find command.")


def test_pki_pkcs12_key_find_password_file(ansible_module):
    """
    :id: 48502270-e49e-48bd-8226-93c46f81f291
    :Title: Test pki pkcs12-key-find command with --pkcs12-password-file option
    :Description: test pki pkcs12-key-find command with password file
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :CaseComponent: \-
    :Requirement: Pki Pkcs12
    :Steps:
        1. pki pkcs12-key-find with --pkcs12-password-file <file>
    :ExpectedResults:
        1. Verify whether pki pkcs12-key-find command with password file.
    """
    p12_file = '/tmp/all_certs.p12'
    password_file = '/tmp/password.txt'
    ansible_module.copy(content=constants.CLIENT_PKCS12_PASSWORD,
                        dest=password_file,
                        force=True)
    pki_server_subsystem = 'pki-server subsystem-cert-export -i {} --pkcs12-file {} ' \
                           '--pkcs12-password {} ca'.format(instance_name, p12_file,
                                                            constants.CLIENT_PKCS12_PASSWORD)
    key_find = 'pki pkcs12-key-find --pkcs12-file {} ' \
               '--pkcs12-password-file {}'.format(p12_file, password_file)
    ansible_module.command(pki_server_subsystem)
    key_out = ansible_module.command(key_find)
    for result in key_out.values():
        if result['rc'] == 0:
            assert "entries found" in result['stdout']
            assert "Key ID:" in result['stdout']
            assert "Friendly Name:" in result['stdout']
        else:
            pytest.fail("Failed to run pki pkcs12-key-find command.")
    ansible_module.command('rm -rf {} {}'.format(p12_file, password_file))


def test_pki_pkcs12_key_find_invalid_pkcs_file_path(ansible_module):
    """
    :id: 6f212be2-465c-4c9e-ba0c-36f66ad5162e
    :Title: Test pki pkcs12-key-find command with invalid pkcs12 file path.
    :Description: test pki pkcs12-key-find command with invalid pkcs12 file path.
    :CaseComponent: \-
    :Requirement: Pki Pkcs12
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki pkcs12-key-find with invalid path
    :ExpectedResults:
         1. Verify whether pki pkcs12-key-find command throws error when ran with the invalid
         pkcs12 file path.
    """
    p12_file = '/tmpfsd/all_certs.p12'
    key_find = 'pki pkcs12-key-find --pkcs12-file {} ' \
               '--pkcs12-password {}'.format(p12_file, constants.CLIENT_PKCS12_PASSWORD)
    key_find_out = ansible_module.command(key_find)
    for result in key_find_out.values():
        if result['rc'] > 0:
            assert "NoSuchFileException: {}".format(p12_file) in result['stderr']
        else:
            pytest.fail("Failed to run pki pkcs12-key-find command.")


def test_bug_1461533_unable_to_find_keys_in_pkcs12_file(ansible_module):
    """
    :id: 1942a8ea-ba54-11e7-9cd0-c85b76bd7797
    :Title: Bug - 1461533 Unable to find the keys in pkcs12 file after deleting the
            any of the subsystem certs form it.
    :Description: While trying to delete the other certificates and keys form pkcs12 file it will
    automatically delete the CA keys form the certificate.
    :Requirement: Pki Pkcs12
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
            1. Export the subsystem certs with keys to the pkcs12 (p12) file.
            2. Check that certificates are present.
            3. Delete the certificate except CA certificate.
            4. Check that CA certificate keys are present in the file.
    :Expectedresults:
                1. It should able to display the CA keys.
    """
    p12_file = '/tmp/all_certs.p12'
    signing_cert_nick = ''
    get_signing_cert_nick = 'certutil  -L -d /var/lib/pki/{}/alias'.format(instance_name)
    cert_nicks = ansible_module.command(get_signing_cert_nick)
    for result in cert_nicks.values():
        if result['rc'] == 0:
            signing_nick = re.findall(r'.*CTu,Cu,Cu', result['stdout'])
            signing_cert_nick = signing_nick[0].split("CTu,Cu,Cu")[0].strip()
    export_subsystem_cert = 'pki-server subsystem-cert-export ca --pkcs12-file {} ' \
                            '--pkcs12-password {} -i {}'.format(p12_file,
                                                                constants.CLIENT_PKCS12_PASSWORD,
                                                                instance_name)
    cert_find = 'pki pkcs12-cert-find --pkcs12-file {} ' \
                '--pkcs12-password {}'.format(p12_file, constants.CLIENT_PKCS12_PASSWORD)

    signing_cert_DN = 'CN=CA Signing Certificate,OU={},O={}'.format(instance_name, constants.CA_SECURITY_DOMAIN_NAME)

    ansible_module.command(export_subsystem_cert)
    show_certs_out = ansible_module.command(cert_find)
    for res in show_certs_out.values():
        if res['rc'] == 0:
            nicks = re.findall(r'Nickname: [\w].*', res['stdout'])
            for nick_name in nicks:
                nick = " ".join(nick_name.split(":")[1:]).strip()
                if nick != signing_cert_nick:
                    delete_certs = 'pki pkcs12-cert-del "{}" --pkcs12-file {} ' \
                                   '--pkcs12-password {}'.format(nick.strip(), p12_file,
                                                                 constants.CLIENT_PKCS12_PASSWORD)
                    cert_out = ansible_module.command(delete_certs)
                    for res in cert_out.values():
                        if res['rc'] == 0:
                            assert 'Deleted certificate "{}"'.format(nick.strip()) in \
                                   res['stdout']
                        else:
                            pytest.fail("Failed to run pki pkcs12-cert-show command.")

                    key_find = 'pki pkcs12-key-find --pkcs12-file {} --pkcs12-password {}'
                    key_find_out = ansible_module.command(key_find.format(p12_file,
                                                                          constants.CLIENT_PKCS12_PASSWORD))
                    for res1 in key_find_out.values():
                        if res1['rc'] == 0:
                            assert "entries found" in res1['stdout']
                            assert "Key ID:" in res1['stdout']
                            assert "Friendly Name: {}".format(signing_cert_DN) in res1['stdout']
                            assert nick.strip() not in res1['stdout']
                        else:
                            pytest.fail("Failed to run pki pkcs12-key-find command.")
    ansible_module.command('rm -rf {}'.format(p12_file))
