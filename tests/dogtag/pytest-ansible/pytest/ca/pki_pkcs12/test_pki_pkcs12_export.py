"""
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 #
 #   Description: Tests following command:
 #                pki pkcs12-export
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

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants
import logging

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


# @pytest.mark.ansible_playbook_setup('init_dir.yaml')
# @pytest.mark.setup
# def test_setup(ansible_playbook):
#     pass


@pytest.fixture(autouse=True)
def init_db2(ansible_module):
    ansible_module.command('pki -d {} -c {} client-init '
                           '--force'.format(db2, constants.CLIENT_DIR_PASSWORD))


def test_pki_pkcs12_export_help(ansible_module):
    """
    :id: a1e383f5-455a-4afe-b253-4b274096e3ef
    :Title: Test pki pkcs12-export --help command
    :Description: test pki pkcs12-export --help command
    :CaseComponent: \-
    :Requirement: Pki Pkcs12
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki pkcs12-export --help
    :ExpectedResults: 
        1. Verify whether pki pkcs12-export --help command shows help options
    """

    export_out = ansible_module.command('pki pkcs12-export --help')
    for result in export_out.values():
        if result['rc'] == 0:
            assert "usage: pkcs12-export [OPTIONS...] [nicknames...]" in result['stdout']
            assert "--append                        Append into an existing PKCS #12 file" in \
                   result['stdout']
            assert "--debug                         Run in debug mode." in result['stdout']
            assert "--help                          Show help message." in result['stdout']
            assert "--no-chain                      Do not include certificate chain" in \
                   result['stdout']
            assert "--no-key                        Do not include private key" in result['stdout']
            assert "--no-trust-flags                Do not include trust flags" in result['stdout']
            assert "-v,--verbose                       Run in verbose mode" in result['stdout']

        else:
            pytest.fail("Failed to run pki pkcs12-export command.!!")


def test_pki_pkcs12_export_without_nick(ansible_module):
    """
    :id: ab5836ea-8f7d-4454-bbdc-b313a849044e
    :Title: Test pki pkcs12-export command without nick
    :Description: test pki pkcs12-export command without nick
    :CaseComponent: \-
    :Requirement: Pki Pkcs12
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki pkcs12-export --pkcs12-file <file> --pkcs12-password <password>
    :ExpectedResults:
        1. Verify whether pki pkcs12-export command exports all certs in p12 file.
    """
    certs = []
    p12_file = '/tmp/all_certs.p12'
    client_cert_find = 'pki -d {} -c {} client-cert-find'
    export_cmd = 'pki -d {} -c {} pkcs12-export --pkcs12-file {} ' \
                 '--pkcs12-password {}'.format(db1, constants.CLIENT_DIR_PASSWORD,
                                               p12_file, constants.CLIENT_PKCS12_PASSWORD)
    import_file = 'pki -d {} -c {} client-cert-import --pkcs12 {} ' \
                  '--pkcs12-password {}'.format(db2, constants.CLIENT_DIR_PASSWORD, p12_file,
                                                constants.CLIENT_PKCS12_PASSWORD)
    get_certs = ansible_module.command(client_cert_find.format(db1, constants.CLIENT_DIR_PASSWORD))
    for r_certs in get_certs.values():
        if r_certs['rc'] == 0:
            certs = re.findall('Nickname: [\w].*', r_certs['stdout'])
            certs = [i.split(":")[1] for i in certs]

    export_out = ansible_module.command(export_cmd)
    for result in export_out.values():
        if result['rc'] == 0:
            assert "Export complete" in result['stdout']
            is_file = ansible_module.stat(path=p12_file)
            for r in is_file.values():
                assert r['stat']['exists']
                cat_output = ansible_module.command(import_file)
                for r1 in cat_output.values():
                    if r1['rc'] == 0:
                        assert "Imported certificates from PKCS #12 file" in r1['stdout']
                get_p12_certs = ansible_module.command('pki pkcs12-cert-find --pkcs12-file {} '
                                                       '--pkcs12-password '
                                                       '{}'.format(p12_file,
                                                                   constants.CLIENT_PKCS12_PASSWORD))
                for r2 in get_p12_certs.values():
                    if r2['rc'] == 0:
                        for cert in certs:
                            assert cert in r2['stdout']
        else:
            pytest.fail("Failed to Export cert using pkcs12-export command.")
    ansible_module.command('rm -rf {}'.format(p12_file))


def test_pki_pkcs12_export_with_nick(ansible_module):
    """
    :id: b5c0545a-73e3-4990-9dc4-a9e54eb32dae
    :Title: Test pki pkcs12-export command with nick
    :Description: test pki pkcs12-export command without nick
    :Requirement: Pki Pkcs12
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :setps:
        1. pki pkcs12-export --pkcs12-file <file> --pkcs12-password <password>
    :ExpectedResults:
        1. Verify whether pki pkcs12-export command exports all certs in p12 file.
    """
    certs = []
    p12_file = '/tmp/all_certs.p12'
    client_cert_find = 'pki -d {} -c {} client-cert-find'

    import_file = 'pki -d {} -c {} client-cert-import --pkcs12 {} ' \
                  '--pkcs12-password {}'.format(db2, constants.CLIENT_DIR_PASSWORD, p12_file,
                                                constants.CLIENT_PKCS12_PASSWORD)
    get_certs = ansible_module.command(client_cert_find.format(db1, constants.CLIENT_DIR_PASSWORD))
    for r_certs in get_certs.values():
        if r_certs['rc'] == 0:
            certs = re.findall('Nickname: [\w].*', r_certs['stdout'])
            certs = [i.split(":")[1].strip() for i in certs]

    for cert in certs:
        export_cmd = 'pki -d {} -c {} pkcs12-export --pkcs12-file {} ' \
                     '--pkcs12-password {} "{}"'.format(db1, constants.CLIENT_DIR_PASSWORD,
                                                        p12_file, constants.CLIENT_PKCS12_PASSWORD,
                                                        cert)
        export_out = ansible_module.command(export_cmd)
        for result in export_out.values():
            if result['rc'] == 0:
                assert "Export complete" in result['stdout']
                is_file = ansible_module.stat(path=p12_file)
                for r in is_file.values():
                    assert r['stat']['exists']
                    cat_output = ansible_module.command(import_file)
                    for r1 in cat_output.values():
                        if r1['rc'] == 0:
                            assert "Imported certificates from PKCS #12 file" in r1['stdout']
                    get_p12_certs = ansible_module.command(
                        client_cert_find.format(db1, constants.CLIENT_DIR_PASSWORD))
                    for r2 in get_p12_certs.values():
                        if r2['rc'] == 0:
                            assert cert in r2['stdout']
                        else:
                            pytest.fail("Failed to run pki pkcs12-cert-find.")
            else:
                pytest.fail("Failed to Export cert using pkcs12-export command.")

    ansible_module.command('rm -rf {}'.format(p12_file))


def test_pki_pkcs12_export_with_mulitple_nicks(ansible_module):
    """
    :id: 1f1d29a2-c780-4dee-9955-60a10d068043
    :Title: Test pki pkcs12-export command with multiple nicks
    :Description: test pki pkcs12-export command with multiple nicks
    :CaseComponent: \-
    :Requirement: Pki Pkcs12
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki pkcs12-export <nick1> <nick2> --pkcs12-file <file> --pkcs12-password <password>
    :ExpectedResults:
        1. Verify whether pki pkcs12-export command exports all certs in p12 file.
    """
    certs = []
    p12_file = '/tmp/all_certs.p12'
    client_cert_find = 'pki -d {} -c {} client-cert-find'.format(db1, constants.CLIENT_DIR_PASSWORD)

    import_file = 'pki -d {} -c {} client-cert-import --pkcs12 {} ' \
                  '--pkcs12-password {}'.format(db2, constants.CLIENT_DIR_PASSWORD, p12_file,
                                                constants.CLIENT_PKCS12_PASSWORD)
    get_certs = ansible_module.command(client_cert_find)
    for r_certs in get_certs.values():
        if r_certs['rc'] == 0:
            certs = re.findall('Nickname: [\w].*', r_certs['stdout'])
            certs = [i.split(":")[1].strip() for i in certs]
    nicks = ""
    for i in certs:
        nicks += " '{}' ".format(i)

    export_cmd = 'pki -d {} -c {} pkcs12-export --pkcs12-file {} ' \
                 '--pkcs12-password {} {}'.format(db1, constants.CLIENT_DIR_PASSWORD,
                                                  p12_file, constants.CLIENT_PKCS12_PASSWORD, nicks)
    export_out = ansible_module.command(export_cmd)
    for result in export_out.values():
        if result['rc'] == 0:
            assert "Export complete" in result['stdout']
            is_file = ansible_module.stat(path=p12_file)
            for r in is_file.values():
                assert r['stat']['exists']
                cat_output = ansible_module.command(import_file)
                for r1 in cat_output.values():
                    if r1['rc'] == 0:
                        assert "Imported certificates from PKCS #12 file" in r1['stdout']
                get_p12_certs = ansible_module.command(client_cert_find)
                for r2 in get_p12_certs.values():
                    if r2['rc'] == 0:
                        for cert in certs:
                            assert cert in r2['stdout']
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail("Failed to Export cert using pkcs12-export command.")

    ansible_module.command('rm -rf {}'.format(p12_file))


def test_pki_pkcs12_export_append(ansible_module):
    """
    :id: 82ab4424-ac46-4007-8323-264618aacd29
    :Title: Test pki pkcs12-export with --append option.
    :Description: test pki pkcs12-export command with append option
    :CaseComponent: \-
    :Requirement: Pki Pkcs12d
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki pkcs12-export <cert_id> --pkcs12-file <file> --pkcs12-password <password> --append
    :ExpectedResults:
        1. Verify whether pki pkcs12-export command exports the cert
    """
    p12_file = '/tmp/ca_admin_cert.p12'
    ansible_module.command('cp -R {}/ca_admin_cert.p12 /tmp/'.format(constants.CA_CLIENT_DIR))

    for nick in [constants.KRA_ADMIN_NICK, constants.OCSP_ADMIN_NICK, constants.TKS_ADMIN_NICK,
                 constants.TPS_ADMIN_NICK]:
        export_cmd = 'pki -d {} -c {} pkcs12-export --pkcs12-file {} ' \
                     '--pkcs12-password {} "{}" --append'.format(db1, constants.CLIENT_DIR_PASSWORD,
                                                                 p12_file,
                                                                 constants.CLIENT_PKCS12_PASSWORD,
                                                                 nick)
        export_out = ansible_module.command(export_cmd)
        for result in export_out.values():
            if result['rc'] == 0:
                assert "Export complete" in result['stdout']

    get_p12_certs = ansible_module.command('pki pkcs12-cert-find --pkcs12-file {} '
                                           '--pkcs12-password '
                                           '{}'.format(p12_file,
                                                       constants.CLIENT_PKCS12_PASSWORD))
    for r2 in get_p12_certs.values():
        if r2['rc'] == 0:
            assert constants.CA_ADMIN_NICK in r2['stdout']
            assert constants.KRA_ADMIN_NICK in r2['stdout']

        else:
            pytest.fail("Failed to Export cert using pkcs12-export command.")
    ansible_module.command('rm -rf {}'.format(p12_file))


@pytest.mark.skip(reason="BZ-1572057")
def test_pki_pkcs12_export_no_chain(ansible_module):
    """
    :id: d80e0ab5-0041-4e90-af9b-509c60d3ed6a
    :Title: Test pki pkcs12-export with --no-chain option.
    :Description: test pki pkcs12-export command
    :CaseComponent: \-
    :Requirement: Pki Pkcs12
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki pkcs12-export <cert_id> --no-chain --pkcs12-password <pass> --pkcs12-file <file>
    :ExpectedResults:
        1. Verify whether pki pkcs12-export command exports the cert without cert chain
    """
    p12_file = '/tmp/all_certs.p12'
    export_cmd = 'pki -d {} -c {} pkcs12-export --pkcs12-file {} ' \
                 '--pkcs12-password {} "{}" --no-chain'.format(db1, constants.CLIENT_DIR_PASSWORD,
                                                               p12_file,
                                                               constants.CLIENT_PKCS12_PASSWORD,
                                                               constants.CA_ADMIN_NICK)
    export_out = ansible_module.command(export_cmd)
    for result in export_out.values():
        if result['rc'] == 0:
            assert "Export complete" in result['stdout']

    is_file = ansible_module.stat(path=p12_file)
    for r in is_file.values():
        assert r['stat']['exists']

        get_p12_certs = ansible_module.command('pki pkcs12-cert-find --pkcs12-file {} '
                                               '--pkcs12-password '
                                               '{}'.format(p12_file,
                                                           constants.CLIENT_PKCS12_PASSWORD))
        for r2 in get_p12_certs.values():
            if r2['rc'] == 0:
                assert 'CA' not in r2['stdout']
                assert constants.CA_ADMIN_NICK in r2['stdout']
            else:
                pytest.fail("Failed to Export cert using pkcs12-export command.")
    ansible_module.command('rm -rf {}'.format(p12_file))


def test_pki_pkcs12_export_no_key(ansible_module):
    """
    :id: ec37238a-6861-4496-8a21-0bb279bec3e7
    :Title: Test pki pkcs12-export with --no-key option.
    :Description: test pki pkcs12-export command
    :CaseComponent: \-
    :Requirement: Pki Pkcs12
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki pkcs12-export <cert_id> --no-key --pkcs12-password <pass> --pkcs12-file <file>
    :ExpectedResults:
        1. Verify whether pki pkcs12-export --no-key command exports the cert without private key
    """
    p12_file = '/tmp/all_certs.p12'
    pkcs12_export = 'pki -d {} -c {} pkcs12-export --pkcs12-file {} ' \
                    '--pkcs12-password {} --no-key'.format(db1, constants.CLIENT_DIR_PASSWORD,
                                                           p12_file,
                                                           constants.CLIENT_PKCS12_PASSWORD)
    export_out = ansible_module.command(pkcs12_export)
    for result in export_out.values():
        if result['rc'] == 0:
            assert "Export complete" in result['stdout']

            is_file = ansible_module.stat(path=p12_file)
            for r in is_file.values():
                assert r['stat']['exists']

                get_p12_certs = ansible_module.command('pki pkcs12-cert-find --pkcs12-file {} '
                                                       '--pkcs12-password '
                                                       '{}'.format(p12_file,
                                                                   constants.CLIENT_PKCS12_PASSWORD))
                for r2 in get_p12_certs.values():
                    if r2['rc'] == 0:
                        assert constants.CA_ADMIN_NICK in r2['stdout']
                        has_key = re.findall("Has Key: [\w].*", r2['stdout'])
                        for key in has_key:
                            assert 'Has Key: false' in key
                    else:
                        pytest.fail("Failed to Export cert using pkcs12-export --no-key command.")
    ansible_module.command('rm -rf {}'.format(p12_file))


def test_pki_pkcs12_export_no_trust_flag(ansible_module):
    """
    :id: 9dbdad30-a684-49e5-b062-4b07a60828c4
    :Title: Test pki pkcs12-export with --no-trust-flags option
    :Description: test pki pkcs12-export command
    :CaseComponent: \-
    :Requirement: Pki Pkcs12
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki pkcs12-export --no-trust-flags --pkcs12-password <pass> --pkcs12-file <file>
    :ExpectedResults:
        1. Verify whether pki pkcs12-export command exports the cert without trust flag.
    """
    p12_file = '/tmp/all_certs.p12'
    pkcs12_export = 'pki -d {} -c {} pkcs12-export --pkcs12-file {} ' \
                    '--pkcs12-password {} --no-trust-flag'.format(db1,
                                                                  constants.CLIENT_DIR_PASSWORD,
                                                                  p12_file,
                                                                  constants.CLIENT_PKCS12_PASSWORD)
    export_out = ansible_module.command(pkcs12_export)
    for result in export_out.values():
        if result['rc'] == 0:
            assert "Export complete" in result['stdout']
        else:
            pytest.fail("Failed to run pki-server pkcs12-export command.")
    ansible_module.command('rm -rf {}'.format(p12_file))


def test_pki_pkcs12_export_password_file(ansible_module):
    """
    :id: 48abe7d0-4c1b-4620-99e9-3efd2c09e21a
    :Title: Test pki pkcs12-export with --pkcs12-password-file option
    :Description: test pki pkcs12-export command
    :Requirement: Pki Pkcs12
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki pkcs12-export --pkcs12-file <file> --pkcs12-password-file <password_file>
    :ExpectedResults:
        1. Verify whether pki pkcs12-export command exports the cert with password file.
    """
    password_file = '/tmp/password.txt'
    p12_file = '/tmp/all_certs.p12'

    ansible_module.copy(content=constants.CLIENT_PKCS12_PASSWORD,
                        dest=password_file,
                        force=True)
    export_cmd = 'pki -d {} -c {} pkcs12-export --pkcs12-file {} ' \
                 '--pkcs12-password-file {} "{}"'.format(db1, constants.CLIENT_DIR_PASSWORD,
                                                         p12_file, password_file,
                                                         constants.CA_ADMIN_NICK)
    export_out = ansible_module.command(export_cmd)
    for result in export_out.values():
        if result['rc'] == 0:
            assert "Export complete" in result['stdout']
            is_file = ansible_module.stat(path=p12_file)
            for r in is_file.values():
                assert r['stat']['exists']
        else:
            pytest.fail("Failed to Export cert using pkcs12-export command.")
    ansible_module.command('rm -rf {}'.format(p12_file))


def test_pki_pkcs12_export_wrong_db_password(ansible_module):
    """
    :id: b000cd0a-4f57-46da-afc7-2672f198559e
    :Title: Test pki pkcs12-export command with wrong db password.
    :Description: test pki pkcs12-export command with wrong db password.
    :CaseComponent: \-
    :Requirement: Pki Pkcs12
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Pki -d <db> -c <wrong_pass> pkcs12-export --pkcs12-password <pass> --pkcs12-file <file>
    :ExpectedResults:
        1. Verify whether pki pkcs12-export command with wrong db password throws error.
    """
    p12_file = '/tmp/all_certs.p12'
    wrong_password = ''.join(random.choice(string.ascii_uppercase +
                                           string.digits +
                                           string.ascii_letters +
                                           string.punctuation)
                             for _ in range(8))
    export_cmd = 'pki -d {} -c "{}" pkcs12-export --pkcs12-file {} ' \
                 '--pkcs12-password {}'.format(db2, wrong_password, p12_file,
                                               constants.CLIENT_PKCS12_PASSWORD)
    export_out = ansible_module.command(export_cmd)
    for result in export_out.values():
        if result['rc'] > 0:
            assert "ERROR: Incorrect password for internal token" in result['stderr']
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail("Failed: Ran pki pkcs12-export command with wrong db password.")


def test_pki_pkcs12_export_with_invalid_nick(ansible_module):
    """
    :id: a983deec-02ed-4454-88aa-9e48c3db0dce
    :Title: Test pki pkcs12-export with invalid nick
    :Description: Test pki pkcs12-export with invalid nick
    :Requirement: Pki Pkcs12
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki pkcs12-cert-export <invalid_nick> --pkcs12-file <file> --pkcs12-password <password>
    :Expectedresults:
            1. It should not export certificate to file.
    """
    p12_file = '/tmp/all_certs.p12'
    wrong_nick = ''.join(random.choice(string.ascii_uppercase +
                                       string.digits +
                                       string.ascii_letters +
                                       string.punctuation)
                         for _ in range(8))
    export_cmd = 'pki -d {} -c {} pkcs12-export --pkcs12-file {} ' \
                 '--pkcs12-password {} "{}"'.format(db2, constants.CLIENT_DIR_PASSWORD, p12_file,
                                                    constants.CLIENT_PKCS12_PASSWORD, wrong_nick)
    export_out = ansible_module.command(export_cmd)
    for result in export_out.values():
        if result['rc'] > 0:
            assert "ERROR: Certificate not found: {}".format(wrong_nick) in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            assert result['rc'] == 0
            pytest.skip("Failed: BZ-1572057")
