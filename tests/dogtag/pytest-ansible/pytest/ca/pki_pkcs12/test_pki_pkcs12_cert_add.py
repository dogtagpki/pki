"""
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Tests pki pkcs12-cert-add CLI
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
import sys

import pytest

from pki.testlib.common.utils import get_random_string
import logging

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

TOPOLOGY = constants.CA_INSTANCE_NAME.split("-")[-2]

if TOPOLOGY == '01':
    instance_name = 'pki-tomcat'
    topology_name = 'topology-01-CA'
else:
    instance_name = constants.CA_INSTANCE_NAME
    topology_name = constants.CA_INSTANCE_NAME


# @pytest.mark.ansible_playbook_setup('init_dir.yaml')
# @pytest.mark.setup
# def test_setup(ansible_playbook):
#     pass


@pytest.fixture(autouse=True)
def init_db2(ansible_module):
    ansible_module.command('pki -d {} -c {} client-init '
                           '--force'.format(db2, constants.CLIENT_DIR_PASSWORD))


@pytest.mark.parametrize('options', ('--help', 'asdfj', ''))
def test_pki_pkcs12_cert_add_help(ansible_module, options):
    """
    :id: 8efdc301-5292-4897-8ea5-9af6d50ed678
    :Title: Test pki pkcs12-cert-add --help command.
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement: Pki Pkcs12
    :CaseComponent: \-
    :Steps:
        1. Run pki pkcs12-cert-add --help
        2. Run pki pkcs12-cert-add ''
        3. Run pki pkcs12-cert-add 'asdfj'
    :ExpectedResult:
        1. It will show the help message
        2. It will show the help message
        3. It will show the error.
    """
    add_out = ansible_module.command('pki pkcs12-cert-add {}'.format(options))
    for result in add_out.values():
        if result['rc'] == 0:
            assert "usage: pkcs12-cert-add <nickname> [OPTIONS...]" in result['stdout']
            assert "--debug                         Run in debug mode." in result['stdout']
            assert "--help                          Show help message." in result['stdout']
            assert "--new-file                      Create a new PKCS #12 file" in result['stdout']
            assert "--no-chain                      Do not include certificate chain" in \
                   result['stdout']
            assert "--no-key                        Do not include private key" in result['stdout']
            assert "--no-trust-flags                Do not include trust flags" in result['stdout']
            assert "--pkcs12-file <path>            PKCS #12 file" in result['stdout']
            assert "--pkcs12-password <password>    PKCS #12 password" in result['stdout']
            assert "--pkcs12-password-file <path>   PKCS #12 password file" in result['stdout']
            assert "-v,--verbose                       Run in verbose mode." in result['stdout']
        else:
            if options not in ['--help']:
                if options == '':
                    assert 'ERROR: Missing certificate nickname.' in result['stderr']
                else:
                    assert 'ERROR: Missing PKCS #12 file.' in result['stderr']


def test_pki_pkcs12_cert_add1(ansible_module):
    """
    :id: 0ae26910-d305-425a-9e2b-1a111c9209cf
    :Title: Test pki pkcs12-add, add cert to existing p12 and import it to the another directory.
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement: Pki Pkcs12
    :CaseComponent: \-
    :Steps:
        1. Create a new nss database.
        2. Import any kra admin (or any) cert to the db.
        3. run pki-cert-add command, it will add the one cert to other
            (here kra admin cert will be added to ca admin cert.)
        4. Create another nss database and import the certificate created in step 3.
        5. Verify that the generated .p12 file has imported both certs using certutil command.
    :ExpectedResult:
        1. Verify weather certificate is get added to the p12 file.

    """
    p12_file = '/tmp/ca_admin_cert.p12'
    ansible_module.command('cp -rf {}/ca_admin_cert.p12 /tmp/'.format(constants.CA_CLIENT_DIR))

    add_cert = ansible_module.command('pki -d {} -c {} pkcs12-cert-add "{}" --pkcs12-file {} '
                                      '--pkcs12-password {}'.format(db1, constants.CLIENT_DIR_PASSWORD,
                                                                    constants.CA_ADMIN_NICK,
                                                                    p12_file, constants.CLIENT_PKCS12_PASSWORD))

    for result in add_cert.values():
        if result['rc'] == 0:
            assert 'Added certificate "{}"'.format(constants.CA_ADMIN_NICK) in result['stdout']

    pkcs12_import = 'pki -d {} -c {} pkcs12-import --pkcs12-file {} ' \
                    '--pkcs12-password {}'.format(db2, constants.CLIENT_DIR_PASSWORD,
                                                  p12_file, constants.CLIENT_PKCS12_PASSWORD)
    pkcs12_import_out = ansible_module.command(pkcs12_import)
    for result in pkcs12_import_out.values():
        if result['rc'] == 0:
            log.info("Successfully Imported the CA Admin cert")

    cert_find = ansible_module.command("pki -d {} -c {} client-cert-find".format(db2, constants.CLIENT_DIR_PASSWORD))
    for result in cert_find.values():
        if result['rc'] == 0:
            assert constants.CA_ADMIN_NICK in result['stdout']
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            assert result['rc'] > 0
            log.error(result['stderr'])
            log.error(result['stdout'])
            pytest.fail()

    ansible_module.command('rm -rf {}'.format(p12_file))


def test_pki_pkcs12_cert_add_password_file(ansible_module):
    """
    :id: 7515d71e-a013-494b-9899-a305d8c84cfb
    :Title: Add cert to new p12 and import it to the another directory using password file.
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement: Pki Pkcs12
    :CaseComponent: \-
    :ExpectedResult: pki pkcs12-cert-add should add the certificate to the file.
    :Steps:
        1. Create a new nss database.
        2. Add CA and KRA certs to the new .p12 file using password file option passed to
           pki pkcs12-cert-add cli.
           (here ca and kra admin cert will be added to all_certs.p12 file.)
        3. Create another nss database and import the certificate created in step 2.
        4. Verify that the generated .p12 file has imported both certs using certutil command.
    """
    password_file = '/tmp/password.txt'
    new_p12_file = '/tmp/all_certs.p12'
    client_cert_find = "pki -d {} -c {} client-cert-find".format(db2,
                                                                 constants.CLIENT_DIR_PASSWORD)

    nicks = [constants.CA_ADMIN_NICK, constants.KRA_ADMIN_NICK]

    ansible_module.copy(content=constants.CLIENT_PKCS12_PASSWORD,
                        dest=password_file,
                        force=True)

    for nick in nicks:
        add_cert_to_file = 'pki -d {} -c {} pkcs12-cert-add "{}" ' \
                           '--pkcs12-file {} ' \
                           '--pkcs12-password-file {}'.format(db1,
                                                              constants.CLIENT_DIR_PASSWORD,
                                                              nick, new_p12_file, password_file)
        add_cert = ansible_module.command(add_cert_to_file)
        for result in add_cert.values():
            if result['rc'] == 0:
                assert 'Added certificate "{}"'.format(nick) in result['stdout']
            else:
                pytest.fail("Failed to export the certificate to file.")

    pkcs12_import = 'pki -d {} -c {} pkcs12-import --pkcs12-file {} ' \
                    '--pkcs12-password {}'.format(db2, constants.CLIENT_DIR_PASSWORD,
                                                  new_p12_file, constants.CLIENT_PKCS12_PASSWORD)
    pkcs12_import_out = ansible_module.command(pkcs12_import)
    for result in pkcs12_import_out.values():
        if result['rc'] == 0:
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    cert_find = ansible_module.command(client_cert_find)
    for result in cert_find.values():
        if result['rc'] == 0:
            assert constants.CA_ADMIN_NICK in result['stdout']
            assert constants.KRA_ADMIN_NICK in result['stdout']

    ansible_module.command('rm -rf {} {}'.format(password_file, new_p12_file))


def test_pki_pkcs12_cert_add_new_file(ansible_module):
    """
    :id: 7a8e6f79-51ef-40fe-ac31-f30863ea72ab
    :Title: Create a new .p12 file with the certificate and keys using --new-file option.
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :CaseComponent: \-
    :Requirement: Pki Pkcs12
    :ExpectedResult:
        1. Verify whether pki pkcs12-cert-add command adds the cert to other p12 file and creates
        a new file.
    :Steps:
        1. Create a new nss database.
        2. Export CA Admin certificate to the file, with --new-file option is passed to the
            pki pkcs12-cert-add cli.
        3. Create another nss database and import the certificate created in step 2.
        4. Verify that the generated .p12 file has imported both certs using certutil command.
    """
    new_p12_file = '/tmp/all_certs.p12'
    client_cert_find = "pki -d {} -c {} client-cert-find".format(db2,
                                                                 constants.CLIENT_DIR_PASSWORD)

    add_cert_to_file = 'pki -d {} -c {} pkcs12-cert-add "{}" --pkcs12-file {} ' \
                       '--pkcs12-password {} --new-file'.format(db1, constants.CLIENT_DIR_PASSWORD,
                                                                constants.CA_ADMIN_NICK,
                                                                new_p12_file,
                                                                constants.CLIENT_PKCS12_PASSWORD)
    add_cert = ansible_module.command(add_cert_to_file)
    for result in add_cert.values():
        if result['rc'] == 0:
            assert 'Added certificate "{}"'.format(constants.CA_ADMIN_NICK) in \
                   result['stdout']
        else:
            pytest.fail("Failed to export the certificate to file.")

    pkcs12_import = 'pki -d {} -c {} pkcs12-import --pkcs12-file {} ' \
                    '--pkcs12-password {}'.format(db2, constants.CLIENT_DIR_PASSWORD,
                                                  new_p12_file, constants.CLIENT_PKCS12_PASSWORD)
    pkcs12_import_out = ansible_module.command(pkcs12_import)
    for result in pkcs12_import_out.values():
        if result['rc'] == 0:
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    cert_find = ansible_module.command(client_cert_find)
    for result in cert_find.values():
        if result['rc'] == 0:
            assert constants.CA_ADMIN_NICK in result['stdout']

    ansible_module.command('rm -rf {}'.format(new_p12_file))


def test_pki_pkcs12_cert_add_no_chain(ansible_module):
    """
    :id: 7ed69e14-34c2-4ab3-93b9-6c2f421a7f6f
    :Title: Add cert to p12 file and import it to the another directory with --no-chain attribute.
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :CaseComponent: \-
    :Requirement: Pki Pkcs12
    :ExpectedResult:
        1. Command should add certificate to file without cert chain.
    :Steps:
        1. Create a new nss database.
        2. Export CA Admin Certificate, pass --no-chain option to pki pkcs12-cert-add cli.
        3. Create another nss database and import the certificate created in step 2.
        4. Verify that the generated .p12 file has imported both certs using certutil command.
    """
    new_p12_file = '/tmp/all_certs.p12'
    client_cert_find = "pki -d {} -c {} client-cert-find".format(db2,
                                                                 constants.CLIENT_DIR_PASSWORD)
    add_cert_to_file = 'pki -d {} -c {} pkcs12-cert-add "{}" --pkcs12-file {} ' \
                       '--pkcs12-password {} --no-chain'.format(db1, constants.CLIENT_DIR_PASSWORD,
                                                                constants.CA_ADMIN_NICK,
                                                                new_p12_file,
                                                                constants.CLIENT_PKCS12_PASSWORD)
    add_cert = ansible_module.command(add_cert_to_file)
    for result in add_cert.values():
        if result['rc'] == 0:
            assert 'Added certificate "{}"'.format(constants.CA_ADMIN_NICK) in \
                   result['stdout']
        else:
            pytest.fail("Failed to export the certificate to file.")

    pkcs12_import = 'pki -d {} -c {} pkcs12-import --pkcs12-file {} ' \
                    '--pkcs12-password {}'.format(db2, constants.CLIENT_DIR_PASSWORD,
                                                  new_p12_file, constants.CLIENT_PKCS12_PASSWORD)
    pkcs12_import_out = ansible_module.command(pkcs12_import)
    for result in pkcs12_import_out.values():
        if result['rc'] == 0:
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    cert_find = ansible_module.command(client_cert_find)
    for result in cert_find.values():
        if result['rc'] == 0:
            assert 'Nickname: CA' not in result['stdout']
            assert constants.CA_ADMIN_NICK in result['stdout']
        else:
            pytest.fail("Failed to run pki client-cert-find command.")
    ansible_module.command('rm -rf {}'.format(new_p12_file))


@pytest.mark.skip(reason="BZ 1572057")
def test_pki_pkcs12_cert_add_no_key(ansible_module):
    """
    :id: 57233db2-fb96-4b1d-8d66-506c3eca6a2b
    :Title: Add cert to p12 and import it to the another directory with --no-key attribute.
    :Requirement: Pki Pkcs12
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :ExpectedResult:
        1. Command should not export certificate key to the file.
    :Steps:
        1. Create a new nss database.
        2. Add CA Admin Cert to the p12 file with --no-key option is passed to pkcs12-cert-add cli.
        3. Create another nss database and import the certificate created in step 2.
        4. Verify that the generated .p12 file has imported both certs using certutil command.
    """
    new_p12_file = '/tmp/all_certs.p12'
    client_cert_find = "certutil -L -d {} ".format(db2)

    add_cert_to_file = 'pki -d {} -c {} pkcs12-cert-add "{}" --pkcs12-file {} ' \
                       '--pkcs12-password {} --no-key'.format(db1, constants.CLIENT_DIR_PASSWORD,
                                                              constants.CA_ADMIN_NICK, new_p12_file,
                                                              constants.CLIENT_PKCS12_PASSWORD)
    add_cert = ansible_module.command(add_cert_to_file)
    for result in add_cert.values():
        if result['rc'] == 0:
            assert 'Added certificate "{}"'.format(constants.CA_ADMIN_NICK) in result['stdout']
        else:
            pytest.fail("Failed to export the certificate to file.")

    pkcs12_import = 'pki -d {} -c {} pkcs12-import --pkcs12-file {} ' \
                    '--pkcs12-password {}'.format(db2, constants.CLIENT_DIR_PASSWORD,
                                                  new_p12_file, constants.CLIENT_PKCS12_PASSWORD)
    pkcs12_import_out = ansible_module.command(pkcs12_import)
    for result in pkcs12_import_out.values():
        if result['rc'] == 0:
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    cert_find = ansible_module.command(client_cert_find)
    for result in cert_find.values():
        if result['rc'] == 0:
            assert 'CA' not in result['stdout']
            assert constants.CA_ADMIN_NICK in result['stdout']
            assert 'u,u,u' not in result['stdout']
        else:
            pytest.fail("Failed to verify key attributes in database.")
    ansible_module.command('rm -rf {}'.format(new_p12_file))


@pytest.mark.skip(reason="BZ 1572057")
def test_pki_pkcs12_cert_add_no_trust_flag(ansible_module):
    """
    :id: aa508fcd-6962-4dda-bb76-d3448143a60d
    :Title: Test pki pkcs12-cert-add --no-trust-flags command
    :CaseComponent: \-
    :Requirement: Pki Pkcs12
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :ExpectedResult:
        1. Command should not add trust flags to the certificate while exporting
    :Steps:
        1. Create a new nss database.
        2. Add CA Admin Cert to the p12 file with --no-trust-flags attribute to pki
        pkcs12-cert-add cli.
        3. Create another nss database and import the certificate created in step 2.
        4. Verify that the generated .p12 file has imported both certs using certutil command.
    """
    new_p12_file = '/tmp/all_certs.p12'
    client_cert_find = "certutil -L -d {} ".format(db2)

    add_cert_to_file = 'pki -d {} -c {} pkcs12-cert-add "{}" --pkcs12-file {} ' \
                       '--pkcs12-password {} ' \
                       '--no-trust-flag'.format(db1, constants.CLIENT_DIR_PASSWORD,
                                                constants.CA_ADMIN_NICK, new_p12_file,
                                                constants.CLIENT_PKCS12_PASSWORD)
    add_cert = ansible_module.command(add_cert_to_file)
    for result in add_cert.values():
        if result['rc'] == 0:
            assert 'Added certificate "{}"'.format(constants.CA_ADMIN_NICK) in result['stdout']
        else:
            pytest.fail("Failed to export the certificate to file.")

    pkcs12_import = 'pki -d {} -c {} pkcs12-import --pkcs12-file {} ' \
                    '--pkcs12-password {}'.format(db2, constants.CLIENT_DIR_PASSWORD,
                                                  new_p12_file, constants.CLIENT_PKCS12_PASSWORD)
    pkcs12_import_out = ansible_module.command(pkcs12_import)
    for result in pkcs12_import_out.values():
        if result['rc'] == 0:
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    cert_find = ansible_module.command(client_cert_find)
    for result in cert_find.values():
        if result['rc'] == 0:
            assert constants.CA_ADMIN_NICK in result['stdout']
            assert ',,' in result['stdout']
        else:
            pytest.fail("Failed to run pki client-cert-find command.")

    ansible_module.command('rm -rf {}'.format(new_p12_file))


def test_pki_pkcs12_cert_add_wrong_pkcs12_password(ansible_module):
    """
    :id: 3f542c9e-b05e-4d2f-8fec-1a33c78a593f
    :Title: Test pki pkcs12-cert-add command with wrong pkcs12 password.
    :Requirement: Pki Pkcs12
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Access the client database with wrong password.
    :ExpectedResult:
        1. Command should throw an error for wrong password
    """

    ansible_module.command('cp -rf {}/ca_admin_cert.p12 '
                           '/{}/ca_admin_cert.p12'.format(constants.CA_CLIENT_DIR, db2))
    add_cert_to_file = 'pki -d {} -c {} pkcs12-cert-add "{}" --pkcs12-file {}/ca_admin_cert.p12 ' \
                       '--pkcs12-password "{}"'.format(db2, constants.CLIENT_DIR_PASSWORD,
                                                       constants.CA_ADMIN_NICK, db2,
                                                       get_random_string(len=10))

    add_cert = ansible_module.command(add_cert_to_file)
    for result in add_cert.values():
        if result['rc'] > 0:
            assert 'ERROR: Unable to validate PKCS #12 file: Digests do not match' in result['stderr']
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            assert 'Added certificate "{}"'.format(constants.CA_ADMIN_NICK) in result['stdout']
            pytest.fail("Failed to export the certificate to file.")


def test_pki_pkcs12_cert_add_wrong_db_password(ansible_module):
    """
    :id: 6b48f7c2-2b05-4e98-aff0-7219529046d9
    :Title: Test pki pkcs12-cert-add command with db password.
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement: Pki Pkcs12
    :CaseComponent: \-
    :Steps:
        1. Add certificate in existing .p12 file with wrong password.
    :ExpectedResult:
        1. Command should throw an error with wrong password.
    """
    wrong_password = get_random_string(len=9)

    ansible_module.command('cp -rf {}/ca_admin_cert.p12 '
                           '/{}/ca_admin_cert.p12'.format(
        constants.CA_CLIENT_DIR, db2))
    add_cert_to_file = 'pki -d {} -c "{}" pkcs12-cert-add "{}" --pkcs12-file {}/ca_admin_cert.p12 ' \
                       '--pkcs12-password {}'.format(db2, wrong_password, constants.CA_ADMIN_NICK,
                                                     db2, constants.CLIENT_PKCS12_PASSWORD)
    add_cert = ansible_module.command(add_cert_to_file)

    for result in add_cert.values():
        if result['rc'] > 0:
            assert "ERROR: Incorrect password for internal token" in result['stderr']
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            assert 'Added certificate "{}"'.format(constants.CA_ADMIN_NICK) in result['stdout']
            pytest.fail("Failed to export the certificate to file.")


def test_pki_pkcs12_cert_add_verbose(ansible_module):
    """
    :id: acc28dcb-7f8f-48c8-8c80-0dfad85ecb22
    :Title: Test pki pkcs12-cert-add --verbose command
    :Requirement: Pki Pkcs12
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Create a new nss database.
        2. Add CA Admin Cert to the p12 file with -v attribute to pki pkcs12-cert-add cli.
        3. Create another nss database and import the certificate created in step 2.
        4. Verify that the generated .p12 file has imported both certs using certutil command.
    :ExpectedResult:
        1. Command with -v option should show debug log messages.
    """
    p12_file = '/tmp/all_certs.p12'
    client_cert_find = "certutil -L -d {} ".format(db2)

    add_cert_to_file = 'pki -d {} -c {} pkcs12-cert-add "{}" --pkcs12-file {} ' \
                       '--pkcs12-password {} -v'.format(db1, constants.CLIENT_DIR_PASSWORD,
                                                        constants.CA_ADMIN_NICK, p12_file,
                                                        constants.CLIENT_PKCS12_PASSWORD)
    add_cert = ansible_module.command(add_cert_to_file)

    for result in add_cert.values():
        if result['rc'] == 0:
            assert 'Added certificate "{}"'.format(constants.CA_ADMIN_NICK) in result['stdout']
        else:
            pytest.fail("Failed to export the certificate to file.")
    pkcs12_import = 'pki -d {} -c {} pkcs12-import --pkcs12-file {} ' \
                    '--pkcs12-password {}'.format(db2, constants.CLIENT_DIR_PASSWORD,
                                                  p12_file, constants.CLIENT_PKCS12_PASSWORD)
    pkcs12_import_out = ansible_module.command(pkcs12_import)
    for result in pkcs12_import_out.values():
        if result['rc'] == 0:
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    cert_find = ansible_module.command(client_cert_find)
    for result in cert_find.values():
        if result['rc'] == 0:
            assert constants.CA_ADMIN_NICK in result['stdout']

    ansible_module.command('rm -rf {}'.format(p12_file))


def test_pki_pkcs12_cert_add_debug(ansible_module):
    """
    :id: 580d9e37-057e-4ee0-a024-233eeb4b2c74
    :Title: Test pki pkcs12-cert-add --debug command.
    :Requirement: Pki Pkcs12
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :ExpectedResult:
        1. Command should show the debug log messages.
    :Steps:
        1. Create a new nss database.
        2. Add CA Admin Cert to the p12 file with --debug attribute to pki pkcs12-cert-add cli.
        3. Create another nss database and import the certificate created in step 2.
        4. Verify that the generated .p12 file has imported both certs using certutil command.
    """
    p12_file = '/tmp/all_certs.p12'
    client_cert_find = "certutil -L -d {} ".format(db2)

    add_cert_to_file = 'pki -d {} -c {} pkcs12-cert-add "{}" --pkcs12-file {} ' \
                       '--pkcs12-password {} --debug'.format(db1, constants.CLIENT_DIR_PASSWORD,
                                                             constants.CA_ADMIN_NICK, p12_file,
                                                             constants.CLIENT_PKCS12_PASSWORD)
    add_cert = ansible_module.command(add_cert_to_file)
    for result in add_cert.values():
        if result['rc'] == 0:
            assert 'Added certificate "{}"'.format(constants.CA_ADMIN_NICK) in \
                   result['stdout']
        else:
            pytest.fail("Failed to export the certificate to file.")
    pkcs12_import = 'pki -d {} -c {} pkcs12-import --pkcs12-file {} ' \
                    '--pkcs12-password {}'.format(db2, constants.CLIENT_DIR_PASSWORD,
                                                  p12_file, constants.CLIENT_PKCS12_PASSWORD)
    pkcs12_import_out = ansible_module.command(pkcs12_import)

    for result in pkcs12_import_out.values():
        if result['rc'] == 0:
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    cert_find = ansible_module.command(client_cert_find)
    for result in cert_find.values():
        if result['rc'] == 0:
            assert constants.CA_ADMIN_NICK in result['stdout']

    ansible_module.command('rm -rf {}'.format(p12_file))
