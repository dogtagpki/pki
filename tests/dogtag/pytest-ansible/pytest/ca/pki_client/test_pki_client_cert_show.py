"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI CLIENT CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki client cli commands needs to be tested:
#   pki client-cert-show
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

non_role_user = '$NonRoleUser$'
default_profile = 'caUserCert'
request_success_log = '[AuditEvent=PROFILE_CERT_REQUEST][SubjectID={}][Outcome=Success][ReqID={}]' \
                      '[ProfileID={}][CertSubject={}] ' \
                      'certificate request made with certificate profiles'


@pytest.mark.ansible_playbook_setup('setup_dirs.yaml')
@pytest.mark.setup
def test_setup(ansible_playbook):
    pass


@pytest.mark.parametrize('args', ['--help', 'asdfa', ''])
def test_pki_client_cert_show_help(ansible_module, args):
    """
    :Title: Test pki client-cert-show --help command
    :Description: test pki client-cert-show command
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :steps:
        1. pki client-cert-show --help
        2. pki client-cert-show sdljfs
        3. pki client-cert-show
    :Expectedresults:
        1. pki client-cert-show --help command lists help options.
        2. It will throw an error.
        3. It will throw an error.
    """

    help_out = ansible_module.command('pki client-cert-show {}'.format(args))
    for result in help_out.values():
        if result['rc'] == 0:
            assert "usage: client-cert-show <nickname> [OPTIONS...]" in result['stdout']
            assert "--cert <path>                  PEM file to store the certificate." in \
                   result['stdout']
            assert "--client-cert <path>           PEM file to store the certificate and" in \
                   result['stdout']
            assert "--help                         Show help options" in result['stdout']
            assert "--pkcs12 <path>                PKCS #12 file to store the certificate" in \
                   result['stdout']
            assert "--pkcs12-password <password>   PKCS #12 file password" in result['stdout']
            assert "--private-key <path>           PEM file to store the private key" in \
                   result['stdout']
            log.info("Successfully ran pki client-cert-show --help command")
        elif args == 'asdfa':
            assert "ObjectNotFoundException: Certificate not found: {}".format(args) in \
                   result['stderr']
        elif args == '':
            assert "Error: Missing certificate nickname." in result['stderr']
        else:
            pytest.xfail("Failed to run pki client-cert-show --help command")


def test_pki_client_cert_show_without_nick(ansible_module):
    """
    :Title: Test pki client-cert-show command without any parameter.
    :Description: test pki client-cert-show command without any parameter.
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki client-cert-show
    :Expectedresults:
        1. Command throws error when ran without having cert nick name.
    """
    show_out = ansible_module.command('pki client-cert-show')
    for result in show_out.values():
        if result['rc'] >= 1:
            assert "Error: Missing certificate nickname" in result['stderr']
            log.info("Success: Unable to run command without nick.")
        else:
            pytest.xfail("Failed: Ran pki client-cert-show command without nick")


def test_pki_client_cert_show_invalid_nick(ansible_module):
    """
    :Title: Test pki client-cert-show command with invalid nickname,BZ:1506710
    :Description: test pki client-cert-show with invalid nickname, BZ: 1506710
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki client-cert-show <invalid_nick>
    :Expectedresults: 
        1. Command should throws error when ran with invalid cert nick name.
    """
    invalid_nick = ''.join(random.choice(string.ascii_uppercase +
                                         string.ascii_letters)
                           for _ in range(20))
    client_cert_del = 'pki -d {} -c {} client-cert-show {}'.format(db1,
                                                                   constants.CLIENT_DIR_PASSWORD,
                                                                   invalid_nick)
    show_output = ansible_module.command(client_cert_del)
    for result in show_output.values():
        if result['rc'] >= 1:
            assert "ObjectNotFoundException: Certificate not found: {}".format(invalid_nick) in \
                   result['stderr']
            log.info("Success: Unable to run command with invalid nick.")
        else:
            pytest.xfail("Failed: Ran pki client-cert-show command with invalid nick")


def test_pki_client_cert_show_valid_nick(ansible_module):
    """
    :Title: Test pki client-cert-show with valid nickname.
    :Description: test pki client-cert-show with valid nickname
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki client-cert-show <valid_nick>
    :Expectedresults: 
        1. Command should shows certificate details.
    """
    cert_show = 'pki -d {} -c {} client-cert-show "{}"'.format(db1,
                                                               constants.CLIENT_DIR_PASSWORD,
                                                               constants.CA_ADMIN_NICK)

    show_out = ansible_module.command(cert_show)
    for result in show_out.values():
        if result['rc'] == 0:
            assert "Serial Number" in result['stdout']
            assert "Nickname: " + constants.CA_ADMIN_NICK in result['stdout']
            assert "Subject DN:" in result['stdout']
            assert "Issuer DN:" in result['stdout']
            log.info("Successfully ran pki client-cert-show command")
        else:
            pytest.xfail("Failed to run pki client-cert-show command")


def test_pki_client_cert_show_without_password(ansible_module):
    """
    :Title: Test pki client-cert-show command without password.
    :Description: test pki client-cert-show without password.
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Expectedresults: 
        1. Command should ran without password shows certificate details.
    """
    cert_show = 'pki -d {} -c {} client-cert-show "{}"'.format(db1, '', constants.CA_ADMIN_NICK)

    show_output = ansible_module.command(cert_show)
    for result in show_output.values():
        if result['rc'] == 0:
            assert "Serial Number" in show_output.stdout_text
            assert "Nickname: " + constants.CA_ADMIN_NICK in show_output.stdout_text
            assert "Subject DN:" in show_output.stdout_text
            assert "Issuer DN:" in show_output.stdout_text
        else:
            log.info("Failed to run {} command.".format(cert_show))


def test_pki_client_cert_show_wrong_password(ansible_module):
    """
    :Title: Test pki client-cert-show command, with wrong certificate db password.
    :Description: test pki client-cert-show with wrong certdb password.
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Expectedresults: 
        1. Command should throws error when ran with wrong db password.
    """
    wrong_password = ''.join(random.choice(string.ascii_uppercase +
                                           string.ascii_letters +
                                           string.punctuation)
                             for _ in range(8))

    show_cmd = 'pki -d {} -c {} client-cert-show "{}"'.format(db1, wrong_password,
                                                            constants.CA_ADMIN_NICK)
    show_output = ansible_module.command(show_cmd)
    for result in show_output.values():
        if result['rc'] >= 1:
            assert "Error: Incorrect client security database password" in result['stderr']
            log.info("Success: Unable to run command with wrong db password.")
        else:
            pytest.xfail("Failed to run {} ".format(show_cmd))


def test_pki_client_cert_show_cert(ansible_module):
    """
    :Title: Test pki client-cert-show --cert command, extracts the certificate to the file.
    :Description: test pki client-cert-show --cert, extracts the certificate to the file.
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d <db> -c <pass> client-cert-show <nick> --cert <file>
    :Expectedresults:
        1. command should exports cert in the .pem file .
    """
    pem_file = '/tmp/ca_admin.pem'
    show_cmd = 'pki -d {} -c {} client-cert-show "{}" ' \
               '--cert {}'.format(db1, constants.CLIENT_DIR_PASSWORD, constants.CA_ADMIN_NICK,
                                  pem_file)

    show_out = ansible_module.command(show_cmd)
    for result in show_out.values():
        if result['rc'] == 0:
            is_file = ansible_module.stat(path=pem_file)
            for res in is_file.values():
                assert res['stat']['exists']
                log.info("Certificate exported to {}".format(pem_file))
            cert_output = ansible_module.command('cat {}'.format(pem_file))
            for r1 in cert_output.values():
                assert "-----BEGIN CERTIFICATE-----" in r1['stdout']
                assert "-----END CERTIFICATE-----" in r1['stdout']
            log.info("Successfully ran pki client-cert-show --cert command")
        else:
            pytest.xfail("Failed to run pki client-cert-show command")


def test_pki_client_cert_show_client_cert(ansible_module):
    """
    :Title: Test pki client-cert-show --client-cert, it should extract the certificate with
    private key.
    :Description: test pki client-cert-show --client-cert, it should extract the cert with
    private key.
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki client-cert-show --client-cert <pem_file>
    :Expectedresults:
        1. command exports cert in the .pem file with certificate and private key.
    """
    client_cert = '/tmp/client_cert.pem'
    cert_show = 'pki -d {} -c {} client-cert-show "{}" ' \
                '--client-cert {}'.format(db1, constants.CLIENT_DIR_PASSWORD,
                                          constants.CA_ADMIN_NICK, client_cert)

    cert_show_out = ansible_module.command(cert_show)
    for result in cert_show_out.values():
        if result['rc'] == 0:
            isfile = ansible_module.stat(path=client_cert)
            for r in isfile.values():
                assert r['stat']['exists']
            log.info("Certificate exported to {}".format(client_cert))
            cert_output = ansible_module.command('cat {}'.format(client_cert))
            for r1 in cert_output.values():
                assert "-----BEGIN PRIVATE KEY-----" in r1['stdout']
                assert "-----END PRIVATE KEY-----" in r1['stdout']
                assert "-----BEGIN CERTIFICATE-----" in r1['stdout']
                assert "-----END CERTIFICATE-----" in r1['stdout']
            log.info("Successfully ran pki client-cert-show --cert command")
        else:
            log.info("Failed to run {} command".format(cert_show))
            pytest.xfail("Failed to run pki client-cert-show command")


def test_pki_client_cert_show_private_key(ansible_module):
    """
    :Title: Test pki client-cert-show command with --private-key option.
    :Description: test pki client-cert-show --private-key option, should export private key in file.
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki client-cert-show --private-key <key_file>
    :Expectedresults:
        1. Command exports private key in the .pem file.
    """
    key_file = '/tmp/ca_cert_key.pem'
    cert_show = 'pki -d {} -c {} client-cert-show "{}" ' \
                '--private-key {}'.format(db1, constants.CLIENT_DIR_PASSWORD,
                                          constants.CA_ADMIN_NICK, key_file)

    cert_show_out = ansible_module.command(cert_show)
    for result in cert_show_out.values():
        if result['rc'] == 0:
            isfile = ansible_module.stat(path=key_file)
            for r in isfile.values():
                assert r['stat']['exists']
            log.info("Certificate exported to {}".format(key_file))
            cert_output = ansible_module.command('cat {}'.format(key_file))
            for r1 in cert_output.values():
                assert "-----BEGIN PRIVATE KEY-----" in r1['stdout']
                assert "-----END PRIVATE KEY-----" in r1['stdout']
            log.info("Successfully ran {} command".format(cert_show))
        else:
            pytest.xfail("Failed to run pki client-cert-show command")


def test_pki_client_cert_show_pkcs12(ansible_module):
    """
    :Title: Test pki client-cert-show command with --pkcs12 option.
    :Description: test pki client-cert-show with --pkcs12 option.
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki client-cert-export --pkcs12 <pkcs12_file> --pkcs12-password <password>
    :Expectedresults:
        1. Command should export certificate to p12 file.
    """
    p12_file = '/tmp/ca_cert.p12'
    cert_show = 'pki -d {} -c {} client-cert-show "{}" ' \
                '--pkcs12 {} --pkcs12-password {}'.format(db1, constants.CLIENT_DIR_PASSWORD,
                                                          constants.CA_ADMIN_NICK, p12_file,
                                                          constants.CLIENT_PKCS12_PASSWORD)

    pkcs12_cert_show = 'pki pkcs12-cert-find --pkcs12-file {} ' \
                       '--pkcs12-password {}'.format(p12_file, constants.CLIENT_PKCS12_PASSWORD)
    cert_show_out = ansible_module.command(cert_show)
    for result in cert_show_out.values():
        if result['rc'] == 0:
            isfile = ansible_module.stat(path=p12_file)
            for r in isfile.values():
                assert r['stat']['exists']
            log.info("Certificate exported to {}".format(p12_file))

            p12_find = ansible_module.command(pkcs12_cert_show)
            for r in p12_find.values():
                if r['rc'] == 0:
                    assert 'Nickname: {}'.format(constants.CA_ADMIN_NICK) in r['stdout']
                else:
                    pytest.xfail("Failed to run pki client-cert-show command")
        else:
            log.info("Successfully ran pki client-cert-show with pkcs12 option.")
