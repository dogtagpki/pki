"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI CLIENT CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki client cli commands needs to be tested:
#   pki client-cert-find
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

local_db = '/tmp/nssdb'
p12_file = '/tmp/all_certs.p12'
admin_pem = '/tmp/ca_admin.pem'

TOPOLOGY = constants.CA_INSTANCE_NAME.split("-")[-2]

if TOPOLOGY == '01':
    instance_name = 'pki-tomcat'
    topology_name = 'topology-01-CA'
    audit_cert_nick = 'auditSigningCert cert-{} CA'.format(instance_name)
else:
    instance_name = constants.CA_INSTANCE_NAME
    topology_name = constants.CA_INSTANCE_NAME
    audit_cert_nick = 'auditSigningCert cert-{} CA'.format(constants.CA_INSTANCE_NAME)

CA_SUBJECT = 'CN=CA Signing Certificate,OU={},O={}'.format(instance_name, constants.CA_SECURITY_DOMAIN_NAME)


@pytest.fixture(autouse=True)
def module_setup(ansible_module):
    client_init = 'pki -d {} -c {} client-init --force'.format(local_db,
                                                               constants.CLIENT_DIR_PASSWORD)
    import_ca = 'pki -d {} -c {} -p {} -h {} client-cert-import ' \
                '--ca-server CA'.format(local_db, constants.CLIENT_DIR_PASSWORD,
                                        constants.CA_HTTP_PORT, 'pki1.example.com')
    export_certs = 'pki-server subsystem-cert-export ca -i {} --pkcs12-file {} ' \
                   '--pkcs12-password {}'.format(instance_name,
                                                 p12_file, constants.CLIENT_PKCS12_PASSWORD)
    import_certs = 'pki -d {} -c {} client-cert-import --pkcs12 {} ' \
                   '--pkcs12-password {}'.format(local_db, constants.CLIENT_DIR_PASSWORD,
                                                 p12_file, constants.CLIENT_PKCS12_PASSWORD)
    ansible_module.command(client_init)
    ansible_module.command(import_ca)
    ansible_module.command(export_certs)
    ansible_module.command(import_certs)
    yield
    ansible_module.command('rm -rf {} {}'.format(p12_file, local_db))


@pytest.mark.parametrize('args', ['--help', '', 'asdf'])
def test_pki_client_cert_find_help(ansible_module, args):
    """
    :Title: Test pki client-cert-find  --help command.
    :Description: test pki client-cert-find --help command
    :Requirement: Pki Client
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki client-cert-find --help
    :Expectedresults:
        1. It should return help message.
    """
    command = 'pki -d {} -c {} client-cert-find {}'.format(constants.NSSDB, constants.CLIENT_DIR_PASSWORD, args)
    find_help_out = ansible_module.command(command)
    for result in find_help_out.values():
        if result['rc'] == 0:
            if args == '--help':
                assert "usage: client-cert-find [OPTIONS...]" in result['stdout']
                assert "--ca     Find CA certificates only" in result['stdout']
                assert "--help   Show help options" in result['stdout']
                log.info("Successfully ran '{}'.".format(command))
            elif args == '':
                assert 'certificate(s) found' in result['stdout']
                assert 'Serial Number:' in result['stdout']
                assert 'Nickname:' in result['stdout']
                assert 'Subject DN:' in result['stdout']
                assert 'Issuer DN:' in result['stdout']
                assert 'Number of entries returned' in result['stdout']
        elif args == 'asdf':
            assert 'Error: Too many arguments specified.' in result['stderr']
            log.info("Successfully run '{}'".format(command))
        else:
            log.error("Failed to run '{}'".format(command))
            pytest.xfail("Failed to run pki client-find --help command.")


def test_pki_client_cert_find_all_certs(ansible_module):
    """
    :Title: Test pki client-cert-find list the certificates in the client security database.
    :Description: test pki client-cert-find, list the certificates from the client db.
    :Requirement: Pki Client
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d <db> -c <pass> client-cert-find
    :Expectedresults:
        1. Command should return the list of the certificates from the database.
    """
    cert_find = 'pki -d {} -c {} client-cert-find'.format(local_db, constants.CLIENT_DIR_PASSWORD)

    cert_find_out = ansible_module.command(cert_find)
    for result in cert_find_out.values():
        if result['rc'] == 0:
            assert "Serial Number: " in result['stdout']
            assert "Nickname: CA" in result['stdout']
            assert "Nickname: {}".format(audit_cert_nick) in result['stdout']
            assert "Subject DN: {}".format(CA_SUBJECT) in result['stdout']
            assert "Issuer DN: {}".format(CA_SUBJECT) in result['stdout']
            assert "Number of entries returned" in result['stdout']
            log.info("Success: Found {} certificate.".format(CA_SUBJECT))
        else:
            log.info("Failed to run pki client-cert-find command.")
            pytest.xfail("Failed to run pki client-cert-find command.")


def test_pki_client_cert_find_notfound(ansible_module):
    """
    :Title: Test pki client-cert-find command when certdb is empty.
    :Description: test pki client-cert-find when cert db is empty
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement: Pki Client
    :Steps:
        1. pki -d <db> -c <pass> client-init --force
        2. pki -d <db> -c <pass> client-cert-find
    :Expectedresults:
        1. Command should not return any entry for the the certificate.
    """
    tmp_db = '/tmp/test_nssdb'
    client_init = 'pki -d {} -c {} client-init --force'.format(tmp_db,
                                                               constants.CLIENT_DIR_PASSWORD)
    cert_find = 'pki -d {} -c {} client-cert-find'.format(tmp_db, constants.CLIENT_DIR_PASSWORD)
    init_out = ansible_module.command(client_init)
    for res in init_out.values():
        if res['rc'] == 0:
            assert 'Client initialized' in res['stdout']
        else:
            log.info("Failed to run pki client-init.")
            pytest.xfail("Failed to run pki client-init.")
    cert_find_out = ansible_module.command(cert_find)
    for result in cert_find_out.values():
        if result['rc'] == 0:
            assert "No certificates found" in result['stdout']
            log.info("Successfully ran the pki client-cert-find command.")
        else:
            log.info("Failed to run pki client-cert-find command.")
            pytest.xfail("Failed to run pki client-cert-find command.")


def test_pki_client_cert_find_ca(ansible_module):
    """
    :Title: Test pki client-cert-find shows the ca certificate with --ca option.
    :Description: pki client-cert-find shows the ca cert with --ca option.
    :Requirement: Pki Client
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d <db> -c <pass> client-cert-find --ca
    :Expectedresults:
        1. It should list only CA certificates from the database.
    """
    client_cert_find = 'pki -d {} -c {} client-cert-find --ca'.format(local_db,
                                                                      constants.CLIENT_DIR_PASSWORD)
    cert_find_out = ansible_module.command(client_cert_find)
    for result in cert_find_out.values():
        if result['rc'] == 0:
            assert "Serial Number: " in result['stdout']
            assert "Nickname: CA" in result['stdout']
            assert "Subject DN: {}".format(CA_SUBJECT) in result['stdout']
            assert "Issuer DN: {}".format(CA_SUBJECT) in result['stdout']
            assert "Number of entries returned 1" in result['stdout']
            log.info("Success: Found {} certificate.".format(CA_SUBJECT))
        else:
            log.info("Failed to run pki client-cert-find command.")
            pytest.xfail("Failed to run pki client-cert-find command.")


def test_pki_client_cert_find_with_wrong_password(ansible_module):
    """
    :Title: Test pki client-cert-find with the wrong password.
    :Description: test pki client-cert-find command with worng password
    :CaseComponent: \-
    :Requirement: Pki Client
    :Setup: Use the subsystems setup in ansible to run subsystem command
    :Steps:
        1. pki -d <db> -c <wrong_pass> client-cert-find
    :Expectedresults:
        1. Command should not list the certificates in the client security database.
    """
    password = utils.get_random_string(len=8)
    cert_find = 'pki -d {} -c {} client-cert-find'.format(local_db, password)
    cert_find_output = ansible_module.command(cert_find)
    for result in cert_find_output.values():
        if result['rc'] >= 1:
            assert "Error: Incorrect client security database password." in result['stderr']
            log.info("Success: Not able to find certificate with wrong password.")
        else:
            log.info("Failed: Able to find certificate with wrong password.")
            pytest.xfail("Failed: Able to find certificate with wrong password.")
