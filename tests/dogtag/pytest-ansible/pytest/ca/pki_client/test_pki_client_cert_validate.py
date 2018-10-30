"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI CLIENT CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki client cli commands needs to be tested:
#   pki client-cert-validate
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Amol Kahat<akahat@redhat.com>
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
p12_file = '/tmp/ca_subsystem.p12'


@pytest.mark.ansible_playbook_setup('setup_dirs.yaml')
@pytest.mark.setup
def test_setup(ansible_playbook):
    pass


@pytest.mark.parametrize('args', ['--help', 'asdfa', ''])
def test_pki_client_cert_validate_help(ansible_module, args):
    """
    :Title: Test pki client-cert-validate --help command
    :Description: test pki client-cert-validate --help command
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement: Pki Client
    :Steps:
        1. pki client-cert-validate --help
        2. pki client-cert-validate asdfa
        3. pki client-cert-validate ''
    :Expectedresults: 
        1. Command should list the help options.
        2. Command should throw an error.
        3. COmmand should throw an error.
    """
    validate_cmd = 'pki client-cert-validate {}'.format(args)

    validate_help_out = ansible_module.command(validate_cmd)
    for result in validate_help_out.values():
        if result['rc'] == 0:
            assert "usage: client-cert-validate nickname" in result['stdout']
            assert "--certusage <certusage>   Certificate usage: CheckAllUsages" in result['stdout']
            assert "SSLServer, SSLServerWithStepUp, SSLClient," in result['stdout']
            assert "SSLCA, AnyCA, StatusResponder, ObjectSigner," in result['stdout']
            assert "UserCertImport, ProtectedObjectSigner," in result['stdout']
            assert "VerifyCA, EmailSigner, EmailRecipient." in result['stdout']
            assert "--help                    Show help options" in result['stdout']
            log.info("Successfully ran {} command".format(validate_cmd))
        elif args == 'asdfa':
            assert 'ObjectNotFoundException: Certificate not found: {}'.format(args) in \
                   result['stderr']
        elif args == '':
            assert 'Error: Invalid number of arguments.' in result['stderr']
        else:
            pytest.xfail("Failed to run {} command".format(validate_cmd))


def test_pki_client_cert_validate_valid_nick(ansible_module):
    """
    :Title: Test pki client-cert-validate with valid nick.
    :Description: test pki client-cert-validate command
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement: Pki Client
    :Steps:
        1. pki client-cert-validate <CA_Admin_nick>
    :Expectedresults:
        1. Verify whether pki client-cert-validate command validates the cert.
    """
    validate_cmd = 'pki -d {} -c {} client-cert-validate "{}"'.format(db1,
                                                                      constants.CLIENT_DIR_PASSWORD,
                                                                      constants.CA_ADMIN_NICK)
    validate_out = ansible_module.command(validate_cmd)
    for result in validate_out.values():
        if result['rc'] == 0:
            assert "Cert has the following usages: SSLClient,EmailSigner,EmailRecipient," \
                   "UserCertImport,VerifyCA,ProtectedObjectSigner,AnyCA" in result['stdout']
            log.info("Successfully ran {} command".format(validate_cmd))
        else:
            pytest.xfail("Failed to run {} command".format(validate_cmd))


def test_pki_client_cert_validate_invalid_nick(ansible_module):
    """
    :Title: Test pki client-cert-vlidate command with invalid nick.
    :Description: test pki client-cert-validate with invalid nick
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement: Pki Client
    :Steps:
        1. pki client-cert-validate <invalid_nick>
    :Expectedresults:
        1. Command should throws error when ran with invalid nick.
    """

    invalid_nick = ''.join(random.choice(string.ascii_uppercase +
                                         string.digits +
                                         string.ascii_letters)
                           for _ in range(20))
    validate_cmd = 'pki -d {} -c {} client-cert-validate {}'.format(db1,
                                                                    constants.CLIENT_DIR_PASSWORD,
                                                                    invalid_nick)
    validate_out = ansible_module.command(validate_cmd)
    for result in validate_out.values():
        if result['rc'] >= 1:
            assert "ObjectNotFoundException: Certificate not found: {}".format(invalid_nick) in \
                   result['stderr']
            log.info("Success: Failed to run with invalid nick")
        else:
            pytest.xfail("Failed: Ran client-cert-validate command with invalid nick.")


def test_pki_client_cert_validate_wrong_password(ansible_module):
    """
    :Title: Test pki client-cert-validate command with wrong password.
    :Description: test pki client-cert-validate command with wrong password.
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement: Pki Client
    :Steps:
        1. pki -d {} -c <wrong_pass> client-cert-validate <CA_Admin_nick>
    :Expectedresults:
        1. Command should throws error when ran with wrong db password.
    """
    wrong_password = ''.join(random.choice(string.ascii_uppercase +
                                           string.ascii_letters)
                             for _ in range(8))
    validate_cmd = 'pki -d {} -c "{}" client-cert-validate {}'.format(db1, wrong_password,
                                                                    constants.CA_ADMIN_NICK)
    validate_output = ansible_module.command(validate_cmd)
    for result in validate_output.values():
        if result['rc'] >= 1:
            assert "Error: Incorrect client security database password" in result['stderr']
            log.info("Success: Unable to run command with wrong db password.")
        else:
            pytest.xfail("Failed: Ran pki client-cert-validate command with wrong db password")


def test_pki_client_cert_validate_certusage_AnyCA(ansible_module):
    """
    :Title: Test pki client-cert-validate command with the --certusage option.
    :Description: test pki client-cert-validate with --certusage option.
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement: Pki Client
    :Steps:
        1. pki client-cert-validate --certusage AnyCA
    :Expectedresults:
        1. Command should validates the cert against usage.
    """
    import_cert = 'pki -d {} -c {} client-cert-import --pkcs12 {} ' \
                  '--pkcs12-password {} '.format(db1, constants.CLIENT_DIR_PASSWORD, p12_file,
                                                 constants.CLIENT_PKCS12_PASSWORD)
    export_to_p12 = 'pki-server subsystem-cert-export ca -i {} --pkcs12-file {} ' \
                    '--pkcs12-password {}'.format(constants.CA_INSTANCE_NAME, p12_file,
                                                  constants.CLIENT_PKCS12_PASSWORD)
    ansible_module.command(export_to_p12)
    ansible_module.command(import_cert)
    validate_cmd = 'pki -d {} -c {} client-cert-validate "CA" ' \
                   '--certusage AnyCA'.format(db1, constants.CLIENT_DIR_PASSWORD,
                                              constants.CA_INSTANCE_NAME)
    validate_output = ansible_module.command(validate_cmd)
    for result in validate_output.values():
        if result['rc'] == 0:
            assert 'Valid certificate: CA'.format(constants.CA_INSTANCE_NAME) in result['stdout']
            log.info("Successfully ran {} command".format(validate_cmd))
        else:
            pytest.xfail("Failed to run pki client-cert-validate command")


@pytest.mark.parametrize('cert,expected', (['CA_AdminV', 'Valid certificate: CA_AdminV'],
                                         ['CA_AdminR', 'Valid certificate: CA_AdminR'],
                                         ['CA_AdminE',
                                          "Invalid certificate: (-8181) Peer's Certificate has "
                                          "expired"]))
def test_pki_client_cert_validate_with_non_ca_cert(ansible_module, cert, expected):
    """
    :Title: Test pki client-cert-validate with non ca-cert
    :Description: Test pki client-cert-validate with non ca-cert
    :Requirement: Pki Client
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Create User Cert.
        2. Import it to the DB.
        3. Run pki client-cert-validate <cert_nick> --certusages AnyCA
    :Expectedresults:
        1 It should validate the certificate of the CA certificate
    """
    cert_validate = 'pki -d {} -c {} client-cert-validate {} ' \
                    '--certusage AnyCA'.format(constants.NSSDB, constants.CLIENT_DIR_PASSWORD, cert)

    validate_out = ansible_module.command(cert_validate)
    for result in validate_out.values():
        if result['rc'] == 0:
            assert expected in result['stdout']
            log.info("Successfully verified the certificate")
        else:
            log.error("Failed to verify cert.")
            log.info(result['stderr'])
            pytest.xfail("Failed to verify cert.")
