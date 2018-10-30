"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI CLIENT CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki client cli commands needs to be tested:
#   pki client-cert-mod
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
import re
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


@pytest.mark.ansible_playbook_setup('setup_dirs.yaml')
@pytest.mark.setup
def test_setup(ansible_playbook):
    pass


@pytest.mark.parametrize('args', ['--help', 'asdfa', ''])
def test_pki_client_cert_mod_help(ansible_module, args):
    """
    :Title: Test pki client-cert-mod with --help command.
    :Description: test pki client-cert-mod command
    :Requirement: Pki Client
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki client-cert-mod --help
        2. pki client-cert-mod 'asdfa'
        3. pki client-cert-mod ''
    :ExpectedResults:
        1. client-cert-mod --help command shows help options.
        2. It should throw 'Error: Unable to modify certificate'
        3. It should throw 'Error: Missing certificate nickname'
    """
    client_mod = 'pki client-cert-mod {}'.format(args)

    mod_help_out = ansible_module.command(client_mod)
    for result in mod_help_out.values():
        if result['rc'] == 0:
            assert "usage: client-cert-mod <nickname> [OPTIONS...]" in result['stdout']
            assert "--help                       Show help options" in result['stdout']
            assert " --trust <trust attributes>   Trust attributes. Default: u,u,u." in result[
                'stdout']
            log.info("Successfully run '{}' command".format(client_mod))
        elif args == '':
            assert 'Error: Missing certificate nickname.' in result['stderr']
        elif args == 'asdfa':
            assert 'Error: Unable to modify certificate' in result['stderr']
        else:
            log.error("Failed to run '{}'.".format(client_mod))
            pytest.xfail("Failed to run pki client-cert-mod --help command.")


def test_pki_client_cert_mod(ansible_module):
    """
    :Title: client-cert-mod command only with certnick
    :Description: test pki client-cert-mod command
    :Requirement: Pki Client
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d <db> -c pass client-cert-mod <nick>
    :ExpectedResults:
        1. client-cert-mod command should not modify the cert.
    """
    client_cmd = 'pki -d {} -c {} client-cert-mod "{}"'.format(db1, constants.CLIENT_DIR_PASSWORD,
                                                               constants.CA_ADMIN_NICK)

    client_out = ansible_module.command(client_cmd)
    for result in client_out.values():
        if result['rc'] == 0:
            assert 'Modified certificate "{}"'.format(constants.CA_ADMIN_NICK) in result['stdout']
            pytest.xfail("Failed to run pki client-cert-mod command.")
        else:
            log.info("Successfully run pki-client-cert-mod command without any args.")


def test_pki_client_cert_mod_without_nick(ansible_module):
    """
    :Title: Test pki client-cert-mod, modify cert without nick
    :Description: test pki client-cert-mod command
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement: Pki Client
    :Steps:
        1. pki -d <db> -c pass client-cert-mod
    :ExpectedResults:
        1. Verify whether pki client-cert-mod command throws error when ran without nick.
    """
    mod_cmd = 'pki -d {} -c {} client-cert-mod'.format(db1, constants.CLIENT_DIR_PASSWORD)

    mod_out = ansible_module.command(mod_cmd)
    for result in mod_out.values():
        if result['rc'] >= 1:
            assert 'Error: Missing certificate nickname' in result['stderr']
        else:
            pytest.xfail("Failed to run pki client-cert-mod without nick.")


def test_pki_client_cert_mod_invalid_nick(ansible_module):
    """
    :Title: Test pki client-cert-mod, modify cert without invalid nick.
    :Description: test pki client-cert-mod command
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement: Pki Client
    :Steps:
        1. pki -d <db> -c <pass> client-cert-mod <invalid_nick>
    :ExpectedResults:
        1. Verify whether pki client-cert-mod command throws error when ran with invalid nick.
    """

    invalid_nick = ''.join(random.choice(string.ascii_uppercase +
                                         string.digits +
                                         string.ascii_letters)
                           for _ in range(20))
    mod_cmd = 'pki -d {} -c {} client-cert-mod "{}"'.format(db1,
                                                            constants.CLIENT_DIR_PASSWORD,
                                                            invalid_nick)
    mod_out = ansible_module.command(mod_cmd)
    for result in mod_out.values():
        if result['rc'] >= 1:
            assert "Error: Unable to modify certificate" in result['stderr']
        else:
            pytest.xfail("Failed to run pki client-cert-mod with invalid nick.")


def test_pki_client_cert_mod_valid_trust(ansible_module):
    """
    :Title: Test pki client-cert-mod, modify certificate with valid trust args.
    :Description: test pki client-cert-mod command
    :Requirement: Pki Client
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d <db> -c <pass> client-cert-mod <nick> --trust 'C,,'
    :ExpectedResults:
        1. Command should modify the trust.
    """

    mod_cmd = 'pki -d {} -c {} client-cert-mod "{}" ' \
              '--trust "C,,"'.format(db1, constants.CLIENT_DIR_PASSWORD,
                                     constants.CA_ADMIN_NICK)

    mod_out = ansible_module.command(mod_cmd)
    for result in mod_out.values():
        if result['rc'] == 0:
            assert 'Modified certificate "{}"'.format(constants.CA_ADMIN_NICK) in result['stdout']
            certutil = ansible_module.command('certutil -L -d {}'.format(db1))
            for res in certutil.values():
                if res['rc'] == 0:
                    assert "{}                         " \
                           "Cu,u,u".format(constants.CA_ADMIN_NICK) in res['stdout']
                else:
                    pytest.xfail("Failed to run pki client-cert-mod command.")
        else:
            pytest.xfail("Failed to run pki client-cert-mod command.")


def test_pki_client_cert_mod_invalid_trust(ansible_module):
    """
    :Title: Test pki client-cert-mod, modify certificate with invalid trust flags.
    :Description: test pki client-cert-mod command
    :Requirement: Pki Client
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d <db> -c <pass> client-cert-mod <nick> --trust 'f,g,'
    :ExpectedResults: 
        1. Command throws error when ran with invalid trust flag.
    """

    cert_mod = 'pki -d {} -c {} client-cert-mod --trust "f,g"'.format(db1,
                                                                      constants.CLIENT_DIR_PASSWORD)

    mod_output = ansible_module.command(cert_mod)
    for result in mod_output.values():
        if result['rc'] == 255:
            log.info("Success: Failed to run client-cert-mod command with invalid trust flag.")
        else:
            assert "Modified failed" in result['stdout']
            pytest.xfail("Error: Able to run client-cert-mod with invalid trust flag")


def test_pki_client_cert_mod_without_private_key(ansible_module):
    """
    :Title: client-cert-mod without private key of the cert
    :Description: client-cert-mod without private key of the cert
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Submit the certificate request.
        2. Approve the certificate request and get the cert id.
        3. Init new client directory.
        4. Import the certificate in new client directory and change the mode.
    :Expectedresults:
        1. Mode on the certificate should change.
    """
    new_db = '/tmp/nssdb_test'
    no = random.randint(11, 999989)
    user = 'testuser{}'.format(no)
    subject = 'UID={},CN={}'.format(user, user)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject)
    init_new_db = 'pki -d {} -c {} client-init --force'.format(new_db,
                                                               constants.CLIENT_DIR_PASSWORD)
    import_ca = 'pki -d {} -c {} -p {} client-cert-import ' \
                '--ca-server RootCA'.format(new_db, constants.CLIENT_DIR_PASSWORD,
                                            constants.CA_HTTP_PORT)
    import_cert = 'pki -d {} -c {} -p {} client-cert-import ' \
                  '--serial {} "{}"'.format(new_db, constants.CLIENT_DIR_PASSWORD,
                                            constants.CA_HTTP_PORT, cert_id, user)

    mod_cmd = 'pki -d {} -c {} client-cert-mod {} --trust "C,,"'
    ansible_module.command(init_new_db)
    ansible_module.command(import_ca)
    ansible_module.command(import_cert)
    cmd_out = ansible_module.command(mod_cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Modified certificate "{}"'.format(user) in result['stdout']
            certutil = ansible_module.command('certutil -L -d {}'.format(db1))
            for res in certutil.values():
                if res['rc'] == 0:
                    certs = re.findall('{}.*'.format(user), res['stdout'])
                    certs = certs[0].strip()

                    assert user in certs
                    assert 'C,,' in certs
                else:
                    pytest.xfail("Failed to run pki client-cert-mod command.")
    ansible_module.command('rm -rf {}'.format(new_db))
