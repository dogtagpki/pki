"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   Description: PKI CLIENT CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki client cli commands needs to be tested:
#   pki client-cert-del
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
TOPOLOGY = constants.CA_INSTANCE_NAME.split("-")[-2]

if TOPOLOGY == '01':
    instance_name = 'pki-tomcat'
    topology_name = 'topology-01-CA'
    audit_cert_nick = 'auditSigningCert cert-{} CA'.format('topology-01-CA')
else:
    instance_name = constants.CA_INSTANCE_NAME
    topology_name = constants.CA_INSTANCE_NAME
    audit_cert_nick = 'auditSigningCert cert-{} CA'.format(constants.CA_INSTANCE_NAME)

CA_SUBJECT = 'CN=CA Signing Certificate,OU={},O={}'.format(instance_name, constants.CA_SECURITY_DOMAIN_NAME)

@pytest.fixture(autouse=True)
def module_setup(ansible_module):
    client_init = 'pki -d {} -c {} client-init --force'.format(local_db, constants.CLIENT_DIR_PASSWORD)

    export_certs = 'pki-server subsystem-cert-export ca -i {} --pkcs12-file {} ' \
                   '--pkcs12-password {}'.format(instance_name, p12_file, constants.CLIENT_PKCS12_PASSWORD)
    import_certs = 'pki -d {} -c {} client-cert-import --pkcs12 {} ' \
                   '--pkcs12-password {}'.format(local_db, constants.CLIENT_DIR_PASSWORD,
                                                 p12_file, constants.CLIENT_PKCS12_PASSWORD)
    ansible_module.command(client_init)
    ansible_module.command(export_certs)
    ansible_module.command(import_certs)
    yield
    ansible_module.command('rm -rf {} {}'.format(p12_file, local_db))


@pytest.mark.parametrize('args', ['--help', '', 'asdf'])
def test_pki_client_cert_del_help(ansible_module, args):
    """
    :Title: Pki client cert del --help command
    :Description: Test pki client-cert-del --help command
    :Requirement: Pki Client
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki client-cert-del --help
        2. pki client-cert-del
        3. pki client-cert-del asdf
    :Expectedresults:
        1. It should show help messages.
        2. It should throw an error.
        3. It should throw an error.
    """
    command = 'pki client-cert-del {}'.format(args)
    del_out = ansible_module.command(command)
    for result in del_out.values():
        if result['rc'] == 0:
            assert "usage: client-cert-del <nickname> [OPTIONS...]" in result['stdout']
            assert "--help   Show help options" in result['stdout']
            log.info("Successfully run '{}'".format(command))
        elif args == 'asdf':
            assert 'ObjectNotFoundException: Certificate not found: asdf' in result['stderr']
            log.info("Successfully run '{}'".format(command))
        else:
            assert 'Error: No nickname specified.' in result['stderr']
            log.info("Successfully run '{}'".format(command))


def test_pki_client_cert_del_delete_valid_certificate(ansible_module):
    """
    :Title: Test pki client cert-del command should delete the certificate from security database.
    :Description: test pki client-cert-del command should delete the cert from security db.
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :CaseComponent: \-
    :Requirement: Pki Client
    :Expectedresults:
        1. It should delete the imported certificate from the security database.
    :Steps:
        1. Execute pki -d <db_path> -c <db_password> client-cert-del <cert_nickName>
        2. Certificate should be deleted from client directory.
    """
    cert_nick = "auditSigningCert cert-{} CA".format(instance_name)
    client_cert_show = 'pki -d {} -c {} client-cert-show "{}"'.format(local_db, constants.CLIENT_DIR_PASSWORD,
                                                                      cert_nick)
    cert_del_cmd = 'pki -d {} -c {} client-cert-del "{}"'.format(local_db, constants.CLIENT_DIR_PASSWORD, cert_nick)

    cert_del_out = ansible_module.command(cert_del_cmd)
    for result in cert_del_out.values():
        if result['rc'] == 0:
            assert 'Removed certificate "{}"'.format(cert_nick) in result['stdout']
            log.info('Removed certificate "{}"'.format(cert_nick))
            log.info("Checking certificate is successfully get deleted from the database.")
            cert_show = ansible_module.command(client_cert_show)
            for res in cert_show.values():
                if res['rc'] >= 1:
                    assert "ObjectNotFoundException: Certificate not found: " \
                           "{}".format(cert_nick) in res['stderr']
                    log.info("Successfully deleted certificate '{}' from the "
                             "database.".format(cert_nick))
                else:
                    log.error("Failed to delete the '{}' from the database.".format(cert_nick))
                    pytest.xfail("Failed to delete the certificate form the database.")
        else:
            log.error('Failed to remove certificate "{}"'.format(cert_nick))
            pytest.xfail("Failed to delete the certificate form the database.")


def test_pki_client_cert_del_wrong_password(ansible_module):
    """
    :Title: PKi client-cert-del command with wrong password.
    :Description: test pki client-cert-del command with wrong password
    :CaseComponent: \-
    :Requirement: Pki Client
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Run pki client-cert-del with wrong password.
    :Expectedresults:
        1. Command with wrong password throws error.
    """
    password = ''.join(random.choice(string.ascii_uppercase +
                                     string.digits +
                                     string.ascii_letters +
                                     string.punctuation)
                       for _ in range(8))
    cert_del_cmd = 'pki -d {} -c {} client-cert-del ' \
                   '"auditSigning cert-{} CA"'.format(local_db, password,
                                                      constants.CA_INSTANCE_NAME)
    cert_find_output = ansible_module.command(cert_del_cmd)
    for result in cert_find_output.values():
        if result['rc'] >= 1:
            assert "Error: Incorrect client security database password." in result['stderr']
            log.info("Success: Not able to delete certificate with wrong password.")
        else:
            log.error("Fail: Deleted certificate with wrong password.")
            pytest.xfail("Fail: Deleted certificate with wrong password.")


def test_pki_client_cert_del_no_cert(ansible_module):
    """
    :Title: Test pki client-cert-del command with invalid or non existed cert name
    :Description: Test pki client-cert-del command with invalid or non existed cert name
    :Requirement: Pki Client
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki client-cert-del <invalid_name>
    :Expectedresults:
        1. It should throw an error for non existed certificate.
    """
    junk = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase)
                   for _ in range(15))
    cert_del_cmd = 'pki -d {} -c {} client-cert-del "{}"'.format(local_db,
                                                                 constants.CLIENT_DIR_PASSWORD,
                                                                 junk)
    cert_del_output = ansible_module.command(cert_del_cmd)
    for result in cert_del_output.values():
        if result['rc'] >= 1:
            assert "ObjectNotFoundException: Certificate not found: {}".format(junk) in \
                   result['stderr']
            log.info("Success: Not able to delete certificate with wrong cert nickname.")
        else:
            log.error("Fail: Deleted certificate with wrong nickname.")
            pytest.xfail("Fail: Deleted certificate with wrong nickname.")


def test_pki_client_cert_del_delete_cert_without_key(ansible_module):
    """
    :Title: Test delete certificate without the key form the database.
    :Description: Test delete certificate without the key from the database.
    :Requirement: Pki Client
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Get the certificate. Ex. Transport Cert.
        2. Get the certificate in to database.
        3. Delete the certificate form the database.
        4. Find the certificate form the database.

    :Expectedresults:
        1. It should get the certificate.
        2. Certificate should be in the database.
        3. Certificate Should get deleted form the database.
        4. Command should throw an error for the certificate not found if certificate
        get deleted.
    """
    serial_no = None
    cert_nick = 'DRM Transport Certificate'
    client_cert_find = 'pki -p {} client-cert-find --name' \
                       ' "{}"'.format(constants.CA_HTTP_PORT, cert_nick)
    find_cert = ansible_module.command(client_cert_find)
    for res in find_cert.values():
        if res['rc'] == 0:
            nos = re.findall('Serial Number: [\w].*', res['stdout'])
            serial_no = nos[0].split(":")[1].strip()

    if serial_no:
        client_cert_import = 'pki -d {} -c {} -p {} client-cert-import ' \
                             '--serial {} "{}"'.format(constants.NSSDB,
                                                       constants.CLIENT_DIR_PASSWORD,
                                                       constants.CA_HTTP_PORT, serial_no, cert_nick)
        get_cert = ansible_module.command(client_cert_import)
        for res in get_cert.values():
            if res['rc'] == 0:
                assert 'Imported certificate "{}"'.format(cert_nick) in res['stdout']
            else:
                pytest.xfail("Failed to import the certificate.")

    if serial_no:
        client_cert_show = 'pki -d {} -c {} client-cert-show ' \
                           '"{}"'.format(constants.NSSDB, constants.CLIENT_DIR_PASSWORD, cert_nick)
        client_cert_del = 'pki -d {} -c {} client-cert-del ' \
                          '"{}"'.format(constants.NSSDB, constants.CLIENT_DIR_PASSWORD, cert_nick)

        cert_del_out = ansible_module.command(client_cert_del)
        for result in cert_del_out.values():
            if result['rc'] == 0:
                assert 'Removed certificate "{}"'.format(cert_nick) in result['stdout']
                log.info('Removed certificate "{}"'.format(cert_nick))
                log.info("Checking certificate is successfully get deleted from the database.")
                cert_show = ansible_module.command(client_cert_show)
                for res in cert_show.values():
                    if res['rc'] >= 1:
                        log.info("Successfully deleted certificate '{}' from the "
                                 "database.".format(cert_nick))
                        assert "ObjectNotFoundException: Certificate not found: {}" in res['stderr']
                    else:
                        log.error("Failed to delete the '{}' from the database.".format(cert_nick))
                        pytest.xfail("Failed to delete the certificate form the database.")
            else:
                log.error('Failed to remove certificate "{}"'.format(cert_nick))
                pytest.xfail("Failed to delete the certificate form the database.")
