"""
 #~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 #   Description: Tests for pki pkcs12-import command
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
import re

import pytest
from pki.testlib.common.utils import get_random_string

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants
import logging

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


@pytest.mark.ansible_playbook_setup('init_dir.yaml')
@pytest.mark.setup
def test_setup(ansible_playbook):
    pass


@pytest.fixture(autouse=True)
def init_db2(ansible_module):
    ansible_module.command('pki -d {} -c {} client-init '
                           '--force'.format(db2, constants.CLIENT_DIR_PASSWORD))


def test_pki_pkcs12_import_help(ansible_module):
    """
    :id: 34438aff-a644-4a2f-ba25-be39dba5805e
    :Title: Test pki pkcs12-import --help command
    :Description: test pki pkcs12-import --help command
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement: Pki Pkcs12
    :CaseComponent: \-
    :Steps:
        1. pki pkcs12-import --help
    :ExpectedResults: 
        1. Verify whether pki pkcs12-import --help command shows the help options.
    """
    import_out = ansible_module.command('pki pkcs12-import --help')
    for result in import_out.values():
        if result['rc'] == 0:
            assert "Usage: pki pkcs12-import [OPTIONS]" in result['stdout']
            assert "--no-trust-flags               Do not include trust flags" in result['stdout']
            assert "--no-user-certs                Do not import user certificates" in \
                   result['stdout']
            assert "--no-ca-certs                  Do not import CA certificates" in \
                   result['stdout']
            assert "-v, --verbose                      Run in verbose mode" in result['stdout']
            assert "--debug                        Run in debug mode." in result['stdout']
            assert "--help                         Show help message." in result['stdout']

        else:
            pytest.fail("Failed to run pkcs12-import command.")


def test_pki_pkcs12_import(ansible_module):
    """
    :id: 2bae38a9-db7b-4541-b394-a98c2122f66b
    :Title: Test pki pkcs12-import command
    :Description: test pki pkcs12-import command
    :CaseComponent: \-
    :Requirement: Pki Pkcs12
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :ExpectedResults:
        1. Verify whether pki pkcs12-import command imports the cert in db.
    """
    p12_file = "/tmp/ca_admin_cert.p12"
    ansible_module.command('cp -rf {}/ca_admin_cert.p12 '
                           '/tmp/ca_admin_cert.p12'.format(constants.CA_CLIENT_DIR))
    import_cmd = 'pki -d {} -c {} pkcs12-import --pkcs12-file {} ' \
                 '--pkcs12-password {}'.format(db2, constants.CLIENT_DIR_PASSWORD, p12_file,
                                               constants.CLIENT_PKCS12_PASSWORD)
    cert_find = 'pki -d {} -c {} client-cert-find'.format(db2, constants.CLIENT_DIR_PASSWORD)
    import_out = ansible_module.command(import_cmd)
    for result in import_out.values():
        if result['rc'] == 0:
            log.info("Successfully ran : {}".format(result['cmd']))
            cert_find_output = ansible_module.command(cert_find)
            for res in cert_find_output.values():
                if res['rc'] == 0:
                    assert "Nickname: {}".format(constants.CA_ADMIN_NICK) in res['stdout']
                    log.info("Successfully found nicknames")
                else:
                    log.error(result['stdout'])
                    log.error(result['stderr'])
                    pytest.fail()

        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
    ansible_module.command('rm -rf {}'.format(p12_file))


def test_pki_pkcs12_import_passowrd_file(ansible_module):
    """
    :id: 56ea152f-5a06-4e9c-a057-08425403f4d4
    :Title: Test pki pkcs12-import command with --pkcs12-password-file option
    :Description: test pki pkcs12-import command
    :CaseComponent: \-
    :Requirement: Pki Pkcs12
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki pkcs12-import --pkcs12-file <file> --pkcs12-password-file <password-file>
    :ExpectedResults:
        1. Verify whether pki pkcs12-import command imports the cert in db with password file.
    """
    password_file = '/tmp/password.txt'
    p12_file = "/tmp/ca_admin_cert.p12"
    ansible_module.command('cp -rf {}/ca_admin_cert.p12 '
                           '/tmp/ca_admin_cert.p12'.format(constants.CA_CLIENT_DIR))
    ansible_module.copy(content=constants.CLIENT_PKCS12_PASSWORD,
                        dest=password_file,
                        force=True)
    import_cmd = 'pki -d {} -c {} pkcs12-import --pkcs12-file {} ' \
                 '--pkcs12-password-file {}'.format(db2, constants.CLIENT_DIR_PASSWORD,
                                                    p12_file, password_file)
    cert_find = 'pki -d {} -c {} client-cert-find'.format(db2, constants.CLIENT_DIR_PASSWORD)
    import_out = ansible_module.command(import_cmd)
    for result in import_out.values():
        if result['rc'] == 0:
            assert result['rc'] == 0
            log.info("Successfully ran : {}".format(result['cmd']))
            cert_find_output = ansible_module.command(cert_find)
            for res in cert_find_output.values():
                if res['rc'] == 0:
                    assert "Nickname: {}".format(constants.CA_ADMIN_NICK) in res['stdout']
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail("Failed to import the cert.")
    ansible_module.command('rm -rf {} {}'.format(p12_file, password_file))


def test_pki_pkcs12_import_no_ca_certs(ansible_module):
    """
    :id: d4af8cbd-93f7-4087-905a-c04d5e36fd74
    :Title: Test pki pkcs12-import command with --no-ca-cert option.
    :Description: test pki pkcs12-import command
    :CaseComponent: \-
    :Requirement: Pki Pkcs12
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki pkcs12-import --no-ca-certs
    :ExpectedResults:
        1. Verify whether pki pkcs12-import --no-ca-certs command imports the cert to db
        without ca cert and the trust flag should be u,u,u.
    """
    password_file = '/tmp/password.txt'
    p12_file = "/tmp/all_certs.p12"
    cert_find = 'pki -d {} -c {} client-cert-find'
    ansible_module.copy(content=constants.CLIENT_PKCS12_PASSWORD,
                        dest=password_file,
                        force=True)
    ansible_module.command('pki -d {} -c {} pkcs12-export --pkcs12-file {} '
                           '--pkcs12-password-file {}'.format(db1, constants.CLIENT_DIR_PASSWORD,
                                                              p12_file, password_file))
    import_cmd = 'pki -d {} -c {} pkcs12-import --pkcs12-file {} --pkcs12-password-file {} ' \
                 '--no-ca-certs'.format(db2, constants.CLIENT_DIR_PASSWORD, p12_file,
                                        password_file)
    import_out = ansible_module.command(import_cmd)
    for result in import_out.values():
        if result['rc'] == 0:
            assert result['rc'] == 0
            log.info("Successfully ran : {}".format(result['cmd']))
            cert_find_out = ansible_module.command(cert_find.format(db2,
                                                                    constants.CLIENT_DIR_PASSWORD))
            for res in cert_find_out.values():
                if res['rc'] == 0:
                    assert "certificate(s) found" in res['stdout']
                    assert 'Nickname: CA' not in res['stdout']
                    assert constants.CA_ADMIN_NICK in res['stdout']
                    assert constants.KRA_ADMIN_NICK in res['stdout']
                else:
                    pytest.fail("Failed to import the cert.")
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail("Failed to import the cert.")
    ansible_module.command('rm -rf {} {}'.format(p12_file, password_file))


def test_pki_pkcs12_import_no_user_certs(ansible_module):
    """
    :id: ef79bc99-3c52-49e2-a1a9-b2162a654e8d
    :Title: Test pki pkcs12-import with --no-user-cert option
    :Description: test pki pkcs12-import command
    :CaseComponent: \-
    :Requirement: Pki Pkcs12
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki pkcs12-import --no-user-certs
    :ExpectedResults:
        1. Verify whether pki pkcs12-import --no-user-certs command imports the cert to db with
        no user cert.
    """
    password_file = '/tmp/password.txt'
    p12_file = "/tmp/all_certs.p12"
    cert_find = 'pki -d {} -c {} client-cert-find'.format(db2, constants.CLIENT_DIR_PASSWORD)
    ansible_module.copy(content=constants.CLIENT_PKCS12_PASSWORD, dest=password_file, force=True)
    ansible_module.command('pki -d {} -c {} pkcs12-export --pkcs12-file {} '
                           '--pkcs12-password-file {}'.format(db1, constants.CLIENT_DIR_PASSWORD,
                                                              p12_file, password_file))
    import_cmd = 'pki -d {} -c {} pkcs12-import --pkcs12-file {} --pkcs12-password-file {} ' \
                 '--no-user-certs'.format(db2, constants.CLIENT_DIR_PASSWORD, p12_file,
                                          password_file)
    import_out = ansible_module.command(import_cmd)
    for result in import_out.values():
        if result['rc'] == 0:
            assert result['rc'] == 0
            log.info('Successfully ran : {}'.format(result['cmd']))
            cert_out = ansible_module.command(cert_find)
            for res in cert_out.values():
                if res['rc'] == 0:
                    assert "Nickname: {}".format(constants.CA_ADMIN_NICK) not in res['stdout']
                    assert 'Nickname: CA' in res['stdout']
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail("Failed to import the cert.")
    ansible_module.command('rm -rf {} {}'.format(p12_file, password_file))


@pytest.mark.skip(reason='BZ-1351039')
def test_pki_pkcs12_import_no_trust_flags(ansible_module):
    """
    :id: 0e43b1ca-ccb9-438a-a932-bf3a98755ded
    :Title: Test pki pkcs12-import command with --no-trust-flags option.
    :Description: test pki pkcs12-import command
    :CaseComponent: \-
    :Requirement: Pki Pkcs12
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Pki pkcs12-import --no-trust-flags
    :ExpectedResults:
        1. Verify whether pki pkcs12-import --no-trust-flags command imports the cert to db.
    """
    password_file = '/tmp/password.txt'
    p12_file = "/tmp/all_certs.p12"
    cert_find = 'certutil -L -d {}'.format(db2)
    ansible_module.copy(content=constants.CLIENT_PKCS12_PASSWORD, dest=password_file, force=True)
    ansible_module.command('pki -d {} -c {} pkcs12-export --pkcs12-file {} '
                           '--pkcs12-password-file {}'.format(db1, constants.CLIENT_DIR_PASSWORD,
                                                              p12_file, password_file))
    import_cmd = 'pki -d {} -c {} pkcs12-import --pkcs12-file {} --pkcs12-password-file {} ' \
                 '--no-trust-flags'.format(db2, constants.CLIENT_DIR_PASSWORD, p12_file,
                                           password_file)

    import_out = ansible_module.command(import_cmd)
    for result in import_out.values():
        if result['rc'] == 0:
            assert result['rc'] == 0
            log.info("Successfully ran : {}".format(result['cmd']))
            cert_out = ansible_module.command(cert_find)
            for res in cert_out.values():
                if res['rc'] == 0:
                    assert "u,u,u" not in res['stdout']
                    assert 'CT,C,C' not in res['stdout']
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail("Failed to import the cert.")
    ansible_module.command('rm -rf {} {}'.format(p12_file, password_file))


def test_pki_pkcs12_import_other_trust_flags(ansible_module):
    """
    :id: ee41ea45-0032-4970-91ae-960af20e9613
    :Title: Test pki pkcs12-import command for trust flags other than u,u,u
    :Description: test pki pkcs12-import command for trust flags other than u,u,u
    :Setup: Use subsystems setup via ansible and a certdb should be created before running
    the command
    :CaseComponent: \-
    :Requirement: Pki Pkcs12
    :Steps:
        1. pki pkcs12-import with trust flags other than u,u,u
    :ExpectedResults:
        1. Verify whether pki pkcs12-import imports the certs to db with trust flags
    other than u,u,u
    """
    certs = {'caSigningCert': 'CTu,Cu,Cu', 'auditSigningCert': 'u,u,Pu'}
    p12_file = '/tmp/all_certs.p12'
    pki_server_subsystem = 'pki-server subsystem-cert-export -i {} --pkcs12-file {} ' \
                           '--pkcs12-password {} ca'.format(instance_name, p12_file,
                                                            constants.CLIENT_PKCS12_PASSWORD)
    import_cmd = 'pki -d {} -c {} pkcs12-import --pkcs12-file {} ' \
                 '--pkcs12-password {}'.format(db2, constants.CLIENT_DIR_PASSWORD, p12_file,
                                               constants.CLIENT_PKCS12_PASSWORD)
    certutil = 'certutil -L -d {}'.format(db2)
    ansible_module.command(pki_server_subsystem)
    import_out = ansible_module.command(import_cmd)
    for result in import_out.values():
        if result['rc'] == 0:
            assert result['rc'] == 0
            log.info("Successfully ran : {}".format(result['cmd']))
            cert_find_out = ansible_module.command(certutil)
            for res in cert_find_out.values():
                if res['rc'] == 0:
                    for name, trust in certs.items():
                        cert_names = re.findall(name + ".*", res['stdout'])[0]
                        assert "{} cert-{} CA".format(name, instance_name) in cert_names
                        assert trust in cert_names
                else:
                    pytest.fail("Failed to run certutil")

        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail("Failed to import the cert.")
    ansible_module.command('rm -rf {}'.format(p12_file))
