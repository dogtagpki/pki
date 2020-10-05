"""
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 #
 #   Description: Testing pki pkcs12-cert-del command
 # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 #
 #   Author: Amol Kahat <akahat@redhat.com>
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


@pytest.mark.parametrize('options', ('--help', 'sadifja', ''))
def test_pki_pkcs12_cert_del_help(ansible_module, options):
    """
    :id: 6cd1773a-4434-449b-a543-a658262546c3
    :Title: Test pki pkcs12-cert-del --help command.
    :Requirement: Pki Pkcs12
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki pkcs12-cert-del --help
        2. pki pkcs12-cert-del ''
        3. pki pkcs12-cert-del 'sadifja'
    :ExpectedResults: 
        1. Verify whether pki pkcs12-cert-del --help command shows help options
    """

    del_out = ansible_module.command('pki pkcs12-cert-del {}'.format(options))
    for result in del_out.values():
        if result['rc'] == 0:
            assert "usage: pkcs12-cert-del <nickname> [OPTIONS...]" in result['stdout']
            assert "--debug                         Run in debug mode." in result['stdout']
            assert "--help                          Show help message." in result['stdout']
            assert "--pkcs12-file <path>            PKCS #12 file" in result['stdout']
            assert "--pkcs12-password <password>    PKCS #12 password" in result['stdout']
            assert "--pkcs12-password-file <path>   PKCS #12 password file" in result['stdout']
            assert "-v,--verbose                       Run in verbose mode." in result['stdout']
        else:
            if options == '':
                assert 'ERROR: Missing certificate nickname.' in result['stderr']
            if options != '--help' and options != '':
                assert 'ERROR: Missing PKCS #12 file.' in result['stderr']


def test_pki_pkcs12_cert_del(ansible_module):
    """
    :id: ef5bd26c-f67f-4f17-8ba7-1bcf8220e443
    :Title: Test pki pkcs12-cert-del command
    :Requirement: Pki Pkcs12
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Create a backup copy of the certificate and delete the certificate form the p12 file.
    :ExpectedResults:
        1. Verify whether pki pkcs12-cert-del command deletes the cert
    """
    ansible_module.command('cp -rf {}/ca_admin_cert.p12 '
                           '/{}/ca_admin_cert.p12'.format(constants.CA_CLIENT_DIR, db2))

    del_cert = ansible_module.command('pki pkcs12-cert-del "{}" --pkcs12-file '
                                      '/{}/ca_admin_cert.p12 --pkcs12-password '
                                      '{}'.format(constants.CA_ADMIN_NICK,
                                                  db2, constants.CLIENT_PKCS12_PASSWORD))

    for result in del_cert.values():
        if result['rc'] == 0:
            assert 'Deleted certificate "{}"'.format(constants.CA_ADMIN_NICK) in result['stdout']
        else:
            pytest.fail("Failed to run pki pkcs12-cert-del command.")
    ansible_module.command('rm -rf {}/ca_admin_cert.p12'.format(db2))


def test_pki_pkcs12_cert_del_password_file(ansible_module):
    """
    :id: 5327d76b-f145-4f39-82ba-e4d35e3a39ef
    :Title: Test pki pkcs12-cert-del command with password file
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement: Pki Pkcs12
    :CaseComponent: \-
    :Setup:
        1. Create a backup of the certificate file and try to delele the certificate with
        --pkcs12-password-file option.
    :ExpectedResults:
        1. Verify whether pki pkcs12-cert-del command deletes the cert with password file
    """

    password_file = '/tmp/password.txt'
    ansible_module.copy(content=constants.CLIENT_PKCS12_PASSWORD, dest=password_file,
                        force=True)
    ansible_module.command('cp -rf {}/ca_admin_cert.p12 '
                           '/{}/ca_admin_cert.p12'.format(constants.CA_CLIENT_DIR, db2))
    client_cert_find = "pki -d {} -c {} client-cert-find".format(db2, constants.CLIENT_DIR_PASSWORD)

    del_cert = ansible_module.command('pki pkcs12-cert-del "{}" --pkcs12-file '
                                      '/{}/ca_admin_cert.p12 --pkcs12-password-file '
                                      '{}'.format(constants.CA_ADMIN_NICK, db2,
                                                  password_file))

    for result in del_cert.values():
        if result['rc'] == 0:
            assert 'Deleted certificate "{}"'.format(constants.CA_ADMIN_NICK) in result['stdout']
        else:
            pytest.fail("Failed to run pki pkcs12-cert-del command.")

    pkcs12_import = 'pki -d {} -c {} pkcs12-import --pkcs12-file {}/ca_admin_cert.p12 ' \
                    '--pkcs12-password {}'.format(db2, constants.CLIENT_DIR_PASSWORD,
                                                  db2, constants.CLIENT_PKCS12_PASSWORD)
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
            assert constants.CA_ADMIN_NICK not in result['stdout']

    ansible_module.command('rm -rf {} {}/ca_admin_cert.p12'.format(password_file, db2))


def test_pki_pkcs12_cert_del_wrong_pkcs_password(ansible_module):
    """
    :id: 06ea2b13-1264-4c5a-9b34-06c1b7c41a0c
    :Title: Test pki pkcs12-cert-del command with wrong pkcs password.
    :Requirement: Pki Pkcs12
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Setup:
        1. Run pki pkcs12-cert-del command with pkcs12-password option and provide wrong password.
    :ExpectedResults:
        1. Verify whether pki pkcs12-export command with wrong pkcs password throws error.
    """
    wrong_password = get_random_string(len=10)

    ansible_module.command('cp -rf {}/ca_admin_cert.p12 '
                           '/{}/ca_admin_cert.p12'.format(constants.CA_CLIENT_DIR, db2))

    del_cert = ansible_module.command('pki pkcs12-cert-del "{}" --pkcs12-file '
                                      '/{}/ca_admin_cert.p12 --pkcs12-password '
                                      '{}'.format(constants.CA_ADMIN_NICK, db2, wrong_password))

    for result in del_cert.values():
        if result['rc'] == 0:
            assert 'Deleted certificate "{}"'.format(constants.CA_ADMIN_NICK) in result['stdout']
            pytest.fail("Failed to run pki pkcs12-cert-del command.")
        else:
            assert 'ERROR: Unable to validate PKCS #12 file: Digests do not match' in \
                   result['stderr']

    ansible_module.command('rm -rf {}/ca_admin_cert.p12'.format(db2))


def test_pki_pkcs12_cert_del_wrong_db_password(ansible_module):
    """
    :id: 21d53907-6cfa-4490-a38c-787add8709bf
    :Title: Test pki pkcs12-cert-del command with wrong db password.
    :Description:
    :CaseComponent: \-
    :Requirement: Pki Pkcs12
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :steps:
        1. Run pki pkcs12-cert-del command with wrong password of db.
    :ExpectedResults:
        1. Verify whether pki pkcs12-export command with wrong db password throws error.
    """
    wrong_password = get_random_string(len=10)
    cert_del = 'pki -d {} -c "{}" pkcs12-cert-del "{}" --pkcs12-file {}/ca_admin_cert.p12 ' \
               '--pkcs12-password {}'.format(db1, wrong_password, constants.CA_ADMIN_NICK, constants.CA_CLIENT_DIR,
                                             constants.CLIENT_PKCS12_PASSWORD)
    del_cert = ansible_module.command(cert_del)

    for result in del_cert.values():
        if result['rc'] > 0:
            assert 'ERROR: Incorrect password for internal token' in result['stderr']
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            assert 'Deleted certificate "{}"'.format(constants.CA_ADMIN_NICK) in result['stdout']
            pytest.fail("Failed to run pki pkcs12-cert-del command.")


def test_bug_1358462_pki_pkcs12_cert_del_with_wrong_nick_name(ansible_module):
    """
    :id: 80ecfde1-ffcb-4f9e-854a-564c06bad690
    :Title: Test pki pkcs12-cert-del command with wrong certificate name. BZ 1358462.
    :Description: Test pki pkcs12-cert-del command with wrong certificate name. BZ 1358462.
    :Requirement: Pki Pkcs12
    :Setup: Use subsystem setup in ansible to run subsystem commands.
    :Steps:
        1. Create the backup of the certificate and try to run pki pkcs12-cert-del with wrong nick.
    :ExpectedResults:
        1. Verify whether pki pkcs12-cert-del command throws the error when certificate
        name is invalid.
    """
    ansible_module.command('cp -rf {}/ca_admin_cert.p12 '
                           '/{}/ca_admin_cert.p12'.format(constants.CA_CLIENT_DIR, db2))

    del_cert = ansible_module.command('pki pkcs12-cert-del "{}abc" --pkcs12-file '
                                      '/{}/ca_admin_cert.p12 --pkcs12-password '
                                      '{}'.format(constants.CA_ADMIN_NICK, db2,
                                                  constants.CLIENT_PKCS12_PASSWORD))
    for result in del_cert.values():
        if result['rc'] == 0:
            pytest.fail("Failed to run pki pkcs12-cert-del command with invalid certificate nick.")
        else:
            assert "ERROR: Certificate not found: %sabc" % constants.CA_ADMIN_NICK in \
                   result['stderr']
    ansible_module.command('rm -rf {}/ca_admin_cert.p12'.format(db2))


def test_pki_pkcs12_cert_del_when_cert_is_already_deleted_from_file(ansible_module):
    """
    :id: 80ecfde1-ffcb-4f9e-854a-564c06bad690
    :Title: Test pki pkcs12-cert-del command when certificate is already deleted and trying to
    delete again.
    :Description: Test pki pkcs12-cert-del command when certificate is already deleted and trying
    to delete again.
    :Requirement: Pki Pkcs12
    :Setup: Use subsystem setup in ansible to run subsystem commands.
    :Steps:
        1. Create the backup copy of the certificate.
        2. Delete the certificate from the file.
        3. Again try to delete the same certificate from the file.
    :ExpectedResults:
        1. Verify weather pki pkcs12-cert-del command throws the error when certificate
           name is already deleted.
    """
    ansible_module.command('cp -rf {}/ca_admin_cert.p12 '
                           '/{}/ca_admin_cert.p12'.format(constants.CA_CLIENT_DIR, db2))

    del_cert = ansible_module.command('pki pkcs12-cert-del "{}" --pkcs12-file '
                                      '/{}/ca_admin_cert.p12 --pkcs12-password '
                                      '{}'.format(constants.CA_ADMIN_NICK, db2,
                                                  constants.CLIENT_PKCS12_PASSWORD))
    for result in del_cert.values():
        if result['rc'] == 0:
            assert 'Deleted certificate "{}"'.format(constants.CA_ADMIN_NICK) in result['stdout']

            cert_del = ansible_module.command('pki pkcs12-cert-del "{}" --pkcs12-file '
                                              '/{}/ca_admin_cert.p12 --pkcs12-password '
                                              '{}'.format(constants.CA_ADMIN_NICK, db2,
                                                          constants.CLIENT_PKCS12_PASSWORD))
            for res in cert_del.values():
                if res['rc'] == 0:
                    pytest.fail("Failed to run pki pkcs12-cert-del command with "
                                 "invalid certificate nick.")
                else:
                    assert "ERROR: Certificate not found: %s" % constants.CA_ADMIN_NICK in \
                           res['stderr']
        else:
            pytest.fail("Failed to run pki pkcs12-cert-del")
    ansible_module.command('rm -rf {}/ca_admin_cert.p12'.format(db2))
