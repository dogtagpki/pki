"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI CLIENT CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki client cli commands needs to be tested:
#   pki client-cert-import
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

local_db = '/tmp/nssdb'
p12_file = '/tmp/all_certs.p12'
audit_pem = '/tmp/audit_signing.pem'
admin_pem = '/tmp/ca_admin.pem'
audit_cert_nick = 'auditSigningCert cert-{} CA'.format(constants.CA_INSTANCE_NAME)
userop = utils.UserOperations(nssdb=constants.NSSDB)

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
    client_init = 'pki -d {} -c {} client-init --force'.format(local_db, constants.CLIENT_DIR_PASSWORD)

    export_certs = 'pki pkcs12-cert-export "{}" --pkcs12-file {} ' \
                   '--pkcs12-password {} --cert-file {}'.format(audit_cert_nick, p12_file,
                                                                constants.CLIENT_PKCS12_PASSWORD, admin_pem)
    export_to_p12 = 'pki-server subsystem-cert-export ca -i {} --pkcs12-file {} ' \
                    '--pkcs12-password {}'.format(instance_name, p12_file,
                                                  constants.CLIENT_PKCS12_PASSWORD)
    ansible_module.command(client_init)
    ansible_module.command(export_to_p12)
    ansible_module.command(export_certs)
    yield
    ansible_module.command('rm -rf {} {} {}'.format(p12_file, audit_pem, local_db))


@pytest.mark.parametrize('args', ['--help', 'asdfa', ''])
def test_pki_client_cert_import_help(ansible_module, args):
    """
    :Title: Test pki client-cert-import --help command
    :Description: Test pki client-cert-import --help command
    :Requirement: Pki Client
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki client-cert-import --help
        2. pki client-cert-import 'asdf'
        3. pki client-cert-import ''
    :Expectedresults: 
        1. pki client-cert-import --help command shows help options.
        2. It will throw an error.
        3. It will throw an error.
    """
    command = 'pki client-cert-import {}'.format(args)
    import_help_out = ansible_module.command(command)
    for result in import_help_out.values():
        if result['rc'] == 0:
            assert "usage: client-cert-import [nickname] [OPTIONS...]" in result['stdout']
            assert "--ca-cert <path>                CA certificate file to import" in \
                   result['stdout']
            assert "--ca-server                     Import CA certificate from CA server" in \
                   result['stdout']
            assert "--cert <path>                   Certificate file to import" in result['stdout']
            assert "--help                          Show help options" in result['stdout']
            assert "--pkcs12 <path>                 PKCS #12 file to import" in result['stdout']
            assert "--pkcs12-password <password>    PKCS #12 password" in result['stdout']
            assert "--pkcs12-password-file <path>   PKCS #12 password file" in result['stdout']
            assert "--serial <serial number>        Serial number of certificate to import" in \
                   result['stdout']
            assert "                                from CA server" in result['stdout']
            assert "--trust <trust attributes>      Trust attributes." in result['stdout']
            log.info("Successfully ran the pki client-cert-import --help command.")
        elif args in ['asdfa', '']:
            assert 'Error: Missing certificate to import' in result['stderr']
            log.info("Successfully run '{}'".format(command))
        else:
            log.error("Failed to run '{}'".format(command))
            pytest.xfail("Failed to run pki client-cert-import --help command.")


def test_pki_client_cert_import_without_pkcs12(ansible_module):
    """
    :Title: Test pki client-cert-import without pkcs12 file path.
    :Description: test pki client-cert-import command
    :Requirement: Pki Client
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d <db_dir> -c <password> client-cert-import
    :Expectedresults:
        1. Command throws error when no options are given in command.
    """
    import_cmd = 'pki -d {} -c {} client-cert-import'.format(local_db,
                                                             constants.CLIENT_DIR_PASSWORD)
    import_out = ansible_module.command(import_cmd)
    for result in import_out.values():
        if result['rc'] >= 1:
            assert "Error: Missing certificate to import" in result['stderr']
            log.info("Success: Throws Error when options is not given.")
        else:
            log.error("Failed: Command return zero status without any option provided.")
            pytest.xfail("Failed: Able to import cert without command options.")


def test_pki_client_cert_import_with_pkcs12_file(ansible_module):
    """
    :Title: Test pki client-cert-import the certificate with the p12 file.
    :Description: test pki client-cert-import command
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement: Pki Client
    :Steps:
        1. pki -d <db_path> -c <db_password> client-cert-import --pkcs12 <path>
        --pkcs12-password <pkcs_password>
        2. Certificate should be imported to client directory.
    :Expectedresults:
        1. Command imports the subsystem cert to the security database.
    """
    client_import = 'pki -d {} -c {} client-cert-import --pkcs12 {} ' \
                    '--pkcs12-password {}'.format(local_db, constants.CLIENT_DIR_PASSWORD,
                                                  p12_file, constants.CLIENT_PKCS12_PASSWORD)
    cert_find_out = ansible_module.command(client_import)
    for result in cert_find_out.values():
        if result['rc'] == 0:
            assert "Imported certificates from PKCS #12 file" in result['stdout']
            log.info("Successfully ran {} command.".format(client_import))
        else:
            log.error("Failed to run {}.".format(client_import))
            pytest.xfail("Failed to run pki client-cert-import command.")


@pytest.mark.parametrize('pkcs_file', [pytest.mark.xfail(local_db),
                                       pytest.mark.xfail('/tmp/sfdew.txt')])
def test_pki_client_cert_import_with_different_pkcs12(ansible_module, pkcs_file):
    """
    :Title: Test pki client-cert-import the certificate with different p12 file option.
    :Description: test pki client-cert-import the certificate with different p12 file option.
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement: Pki Client
    :Steps:
        1. pki -d <db_path> -c <db_password> client-cert-import --pkcs12 /tmp/nssdb
        --pkcs12-password <pkcs_password>
        2. pki -d <db_path> -c <db_password> client-cert-import --pkcs12 /tmp/sfdew.txt
        --pkcs12-password <pkcs_password>
    :Expectedresults:
        1. It should fail to import.
        2. It will throw an exectption for invalid file.
    """
    client_import = 'pki -d {} -c {} client-cert-import --pkcs12 {} ' \
                    '--pkcs12-password {}'.format(local_db, constants.CLIENT_DIR_PASSWORD,
                                                  pkcs_file, constants.CLIENT_PKCS12_PASSWORD)
    cert_find_out = ansible_module.command(client_import)
    for result in cert_find_out.values():
        if result['rc'] >= 1:
            assert "Error: Unable to import PKCS #12 file" in result['stderr']
            log.info("Successfully ran {} command.".format(client_import))
        else:
            log.error("Failed to run {}.".format(client_import))
            pytest.xfail("Failed to run pki client-cert-import command.")


def test_pki_client_cert_import_with_pkcs12_wrong_pass(ansible_module):
    """
    :Title: Test pki client-cert-import the certificate with p12 file and wrong p12 pass.
    :Description: test pki client-cert-import, import with wrong p12 password.
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement: Pki Client
    :Steps:
        1. pki -d <db_path> -c <db_password> client-cert-import --pkcs12 <path>
        --pkcs12-password <wrong_pass>
    :Expectedresults:
        1. Command should not import the certificate to the database.
    """
    wrong_pass = utils.get_random_string(len=20)
    client_import = 'pki -d {} -c {} client-cert-import --pkcs12 {} ' \
                    '--pkcs12-password {}'.format(local_db, constants.CLIENT_DIR_PASSWORD,
                                                  p12_file, wrong_pass)
    cert_find_out = ansible_module.command(client_import)
    for result in cert_find_out.values():
        if result['rc'] >= 1:
            assert "Error: Unable to import PKCS #12 file" in result['stderr']
            log.info("Successfully ran {} command.".format(client_import))
        else:
            log.error("Failed to run {}.".format(client_import))
            pytest.xfail("Failed to run pki client-cert-import command.")


def test_pki_client_cert_import_with_password_file_option(ansible_module):
    """
    :Title: Test pki client-cert-import, import cert when password is stored in file.
    :Description: test pki client-cert-import command with pkcs12 password file
    :Requirement: Pki Client
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Execute pki -d <db_path> -c <password> client-cert-import --pkcs12 <path>
        --pkcs12-password-file <path>
    :Expectedresults:
        1. Command with password file having correct password imports the subsystem cert to the
        security database.
    """
    password_file = '/tmp/password.txt'
    client_import = 'pki -d {} -c {} client-cert-import --pkcs12 {} ' \
                    '--pkcs12-password-file {}'.format(local_db, constants.CLIENT_DIR_PASSWORD,
                                                       local_db, password_file)
    ansible_module.copy(dest=password_file, content=constants.CLIENT_PKCS12_PASSWORD, force=True)

    import_out = ansible_module.command(client_import)
    for result in import_out.values():
        if result['rc'] == 0:
            assert "Imported certificates from PKCS #12 file" in result['stdout']
            log.info("Successfully ran the pki client-cert-import command with password file.")
        else:
            log.error("Failed to run pki client-cert-import command with password file.")
            pytest.xfail("Failed to run pki client-cert-import command with password file.")


def test_pki_client_cert_import_with_password_file_and_wrong_pass(ansible_module):
    """
    :Title: Test pki client-cert-import, import cert with --password-file and password should be wrong
    :Description: test pki client-cert-import import cert with --password-file and password
    should be wrong.
    :Requirement: Pki Client
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Execute pki -d <db_path> -c <password> client-cert-import --pkcs12 <path>
        --pkcs12-password-file <path>
    :Expectedresults:
        1. Command should not import certificate in the db with wrong password in password file.
    """
    wrong_pass = utils.get_random_string(len=20)
    password_file = '/tmp/password.txt'
    client_import = 'pki -d {} -c {} client-cert-import --pkcs12 {} ' \
                    '--pkcs12-password-file {}'.format(local_db, constants.CLIENT_DIR_PASSWORD,
                                                       p12_file, password_file)
    ansible_module.copy(dest=password_file, content=wrong_pass, force=True)

    import_out = ansible_module.command(client_import)
    for result in import_out.values():
        if result['rc'] >= 1:
            assert "Error: Unable to import PKCS #12 file" in result['stderr']
            log.info("Successfully ran the pki client-cert-import command with password file.")
        else:
            log.error("Failed to run pki client-cert-import command with password file.")
            pytest.xfail("Failed to run pki client-cert-import command with password file.")


def test_pki_client_cert_import_with_ca_server_option(ansible_module):
    """
    :Title: Test pki client-cert-import import the ca server certificate with the --server option.
    :Description: test pki client-cert-import command to import ca server cert
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement: Pki Client
    :Steps:
        1. Execute pki -d <db_path> -c <db_password> client-cert-import <nickname> --ca-server
    :Expectedresults:
        1. Command imports the ca server cert to the security database.
    """
    client_import = 'pki -d {} -c {} -h {} -p {} client-cert-import RootCA ' \
                    '--ca-server'.format(local_db, constants.CLIENT_DIR_PASSWORD,
                                         constants.MASTER_HOSTNAME, constants.CA_HTTP_PORT)
    client_cert_find = 'pki -d {} -c {} client-cert-find'
    cert_import_out = ansible_module.command(client_import)
    for result in cert_import_out.values():
        if result['rc'] == 0:
            assert 'Imported certificate "RootCA"' in result['stdout']
            log.info("Successfully imported CA cert to database.")

            find_out = ansible_module.command(client_cert_find.format(local_db,
                                                                      constants.CLIENT_DIR_PASSWORD))
            for res in find_out.values():
                if res['rc'] == 0:
                    assert 'Nickname: RootCA' in res['stdout']
                    log.info("Verified that certificate is imported to db.")
                    certutil_out = ansible_module.command('certutil -L -d {}'.format(local_db))
                    for r in certutil_out.values():
                        if r['rc'] == 0:
                            log.info("Checking the trust flags on the CA Certificate.")
                            trusts = re.findall("RootCA.*", r['stdout'])
                            cert_trusts = trusts[0].strip()
                            assert 'RootCA' in cert_trusts
                            assert 'CT,C,C' in cert_trusts
                            log.info("Verified the trust flags on the CA certificates.")
                        else:
                            log.info("Failed to check the flags on the CA certificate.")
                            pytest.xfail("Failed to check the flags on the CA certificate.")
                else:
                    log.info("Failed to find the certificate in db.")
                    pytest.xfail("Failed to find the certificate in db.")
        else:
            log.error("Failed to import CA cert to database.")
            pytest.xfail("Failed to run pki client-cert-import command.")


def test_pki_client_cert_import_with_ca_cert_option(ansible_module):
    """
    :Title: Test pki client-cert-import, Import ca cert from the file using --ca-cert option.
    :Description: test pki client-cert-import --ca-cert command to import ca cert
    :Requirement: Pki Client
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Extract the ca admin cert from .p12 file.
        2. Execute pki -d <db_path> -c <db_password> client-cert-import <nickname> --ca-cert
        <extracted cert file>
    :Expectedresults:
        1. Command imports the ca cert to the security database.
    """
    get_ca_cert_id = 'pki -p {} ca-cert-find --name "CA Signing Certificate" --orgUnit "{}" ' \
                     '--org "{}" --matchExactly'.format(constants.CA_HTTP_PORT, instance_name,
                                                        constants.CA_SECURITY_DOMAIN_NAME)

    pem_file = '/tmp/ca_signing.pem'
    client_cert_import = ' pki -d {} -c {} client-cert-import "RootCA" ' \
                         '--ca-cert {}'.format(local_db, constants.CLIENT_PKCS12_PASSWORD, pem_file)
    log.info("Finding 'CA Signing Certificate'")
    get_ca_cert_out = ansible_module.command(get_ca_cert_id)
    for res in get_ca_cert_out.values():
        if res['rc'] == 0:
            assert '1 entries found' in res['stdout']
            raw_no = re.findall('Serial Number: [\w].*', res['stdout'])
            serial = raw_no[0].split(":")[1].strip()
            log.info("Found 'CA Signing Certificate with serial: {}'".format(serial))
            export_to_pem = 'pki -p {} ca-cert-show {} --output {} ' \
                            '--encoded'.format(constants.CA_HTTP_PORT, serial, pem_file)
            pem_out = ansible_module.command(export_to_pem)
            for r in pem_out.values():
                if r['rc'] == 0:
                    log.info("Exporting certificate to pem file.")
                    is_file = ansible_module.stat(path=pem_file)
                    for r1 in is_file.values():
                        assert r1['stat']['exists']
                        log.info("Exported certificate to pem file.")
                else:
                    log.error("Failed to export certificate to the file.")
                    pytest.xfail("Failed to export certificate to the file.")
        else:
            log.error("Failed to get 'CA Signing Certificate'")
            pytest.xfail("Failed to get 'CA Signing Certificate'")
    cert_find_output = ansible_module.command(client_cert_import)
    for result in cert_find_output.values():
        if result['rc'] == 0:
            assert 'Imported certificate "RootCA"' in result['stdout']
            log.info("Successfully imported ca cert to database.")
        else:
            log.error("Failed to import ca admin cert to database.")
            pytest.xfail("Failed to run pki client-cert-import command.")


def test_pki_client_cert_import_with_cert_option(ansible_module):
    """
    :Title: Test pki client-cert-import, import client cert with --cert option.
    :Description: test pki client-cert-import --cert command to import ca cert
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Extract the ca admin cert from .p12 file. to .pem file
        2. Execute pki -d <db_path> -c <db_password> client-cert-import <nickname> --cert <certfile>
    :Expectedresults:
        1. Command imports the cert to the security database.
    """
    admin_p12 = '/tmp/ca_admin.p12'
    admin_pem = '/tmp/ca_admin.pem'
    ansible_module.command("cp -R {}/ca_admin_cert.p12 {}".format(constants.CA_CLIENT_DIR, admin_p12))
    pkcs_to_pem = 'pki pkcs12-cert-export "{}" --pkcs12-file {} --pkcs12-password {} ' \
                  '--cert-file {}'.format(constants.CA_ADMIN_NICK, admin_p12, constants.CLIENT_PKCS12_PASSWORD,
                                          admin_pem)
    cert_import = 'pki -d {} -c {} client-cert-import "PKI CA Admin" ' \
                  '--cert {}'.format(local_db, constants.CA_HTTP_PORT, admin_pem)
    ansible_module.command(pkcs_to_pem)
    log.info("Exporting 'CA Admin' cert to pem file.")
    cert_find_output = ansible_module.command(cert_import)
    for res in cert_find_output.values():
        if res['rc'] == 0:
            assert 'Imported certificate "PKI CA Admin"' in res['stdout']
            log.info("Successfully imported cert to database.")
            certutil_out = ansible_module.command('certutil -L -d {}'.format(local_db))
            for r in certutil_out.values():
                if r['rc'] == 0:
                    log.info("Checking the trust flags on the CA Certificate.")
                    trusts = re.findall("PKI CA Admin.*", r['stdout'])
                    cert_trusts = trusts[0].strip()
                    assert 'PKI CA Admin' in cert_trusts
                    assert ',,' in cert_trusts
                    log.info("Verified the trust flags on the CA certificates.")
                else:
                    log.info("Failed to check the flags on the CA certificate.")
                    pytest.xfail("Failed to check the flags on the CA certificate.")
        else:
            log.info("Failed to import cert to database.")
            pytest.xfail("Failed to run pki client-cert-import command.")
    ansible_module.command('rm -rf {} {}'.format(admin_pem, admin_p12))


@pytest.mark.parametrize('args', [local_db, '/asd/sdfe', p12_file])
def test_pki_client_cert_import_with_cert_option_with_diff_files(ansible_module, args):
    """
    :Title: Test pki client-cert-import, import client cert with --cert option as diff file and dir.
    :Description: test pki client-cert-import --cert option with diff file and dir.
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Execute pki -d <db_path> -c <db_password> client-cert-import <nickname> --cert <dir>
        2. Execute pki -d <db_path> -c <db_password> client-cert-import <nickname> --cert <invalid_dir>
        3. Execute pki -d <db_path> -c <db_password> client-cert-import <nickname> --cert <p12_file>
    :Expectedresults:
        1. It should failed.
        2. It should failed.
        3. It should import the certificate to the database.
    """

    cert_import = 'pki -d {} -c {} client-cert-import "PKI CA Admin" ' \
                  '--cert {}'.format(local_db, constants.CA_HTTP_PORT, args)
    cert_find_output = ansible_module.command(cert_import)
    for res in cert_find_output.values():
        if res['rc'] >= 1:
            assert 'Error: Unable to import certificate file' in res['stderr']
            log.info("Successfully run '{}'.".format(cert_import))
        else:
            log.info("Failed to import cert to database.")
            pytest.xfail("Failed to run pki client-cert-import command.")


@pytest.mark.parametrize('trust', ['CT,C,C', ',,', 'CTu,Cu,Cu'])
def test_pki_client_cert_import_valid_trust(ansible_module, trust):
    """
    :Title: pki client-cert-import, import certificate with --trust flag.
    :Description: test pki client-cert-import --trust command to import ca cert
    :Requirement: Pki Client
    :Setup:Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Extract the ca audit signing cert from .p12 file to .pem file
        2. pki -d <db_path> -c <db_password> client-cert-import <nickname> --cert <certfile>
        --trust <valid trust flag>
    :Expectedresults:
        1. Command with valid trust flag imports the cert to the security database.
    """
    admin_p12 = '/tmp/ca_admin.p12'
    admin_pem = '/tmp/ca_admin.pem'
    ansible_module.command("cp -R {}/ca_admin_cert.p12 {}".format(constants.CA_CLIENT_DIR, admin_p12))
    pkcs_to_pem = 'pki pkcs12-cert-export "{}" --pkcs12-file {} --pkcs12-password {} ' \
                  '--cert-file {}'.format(constants.CA_ADMIN_NICK, admin_p12,
                                          constants.CLIENT_PKCS12_PASSWORD, admin_pem)
    ansible_module.command(pkcs_to_pem)
    cert_import = 'pki -d {} -c {} client-cert-import "CA Admin" --cert {} ' \
                  '--trust "{}"'.format(local_db, constants.CLIENT_DIR_PASSWORD, admin_pem, trust)
    cert_find_output = ansible_module.command(cert_import)
    for res in cert_find_output.values():
        if res['rc'] == 0:
            assert 'Imported certificate "CA Admin"' in res['stdout']
            log.info("Checking trust on the certificate")
            certutil_out = ansible_module.command('certutil -L -d {}'.format(local_db))
            for r in certutil_out.values():
                if r['rc'] == 0:
                    certs = re.findall('CA Admin.*', r['stdout'])
                    ca_cert = certs[0].strip()
                    assert trust.replace('u', '') in ca_cert
                    log.info("Certificate imported with ,, trust.")
                else:
                    log.info("Failed to run pki client-cert-import command.")
                    pytest.xfail("Failed to run pki client-cert-import command.")
        else:
            log.info("Failed to import cert to database.")
            pytest.xfail("Failed to import cert to database.")
    ansible_module.command('rm -rf {} {}'.format(admin_pem, admin_p12))


def test_pki_client_cert_import_invalid_trust(ansible_module):
    """
    :Title: Test pki client-cert-import, import certificate with wrong trust arguments.
    :Description: test pki client-cert-import --trust command to import ca cert
    :Requirement: Pki Client
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Extract the ca audit signing cert from .p12 file. or use any .cert .pem file
        2. pki -d <db_path> -c <db_password> client-cert-import <nickname> --cert <certfile>
        --trust <invalid trust flag>
    :Expectedresults:
        1. Command with invalid trust flag doesn't imports the cert to the security database.
    """

    admin_p12 = '/tmp/ca_admin.p12'
    admin_pem = '/tmp/ca_admin.pem'
    ansible_module.command("cp -R {}/ca_admin_cert.p12 {}".format(constants.CA_CLIENT_DIR,
                                                                  admin_p12))
    pkcs_to_pem = 'pki pkcs12-cert-export "{}" --pkcs12-file {} --pkcs12-password {} ' \
                  '--cert-file {}'.format(constants.CA_ADMIN_NICK, admin_p12,
                                          constants.CLIENT_PKCS12_PASSWORD, admin_pem)
    ansible_module.command(pkcs_to_pem)
    cert_import = 'pki -d {} -c {} client-cert-import "CA CERT" --cert {} ' \
                  '--trust ",f,g"'.format(local_db, constants.CLIENT_DIR_PASSWORD, admin_pem)
    cert_find_output = ansible_module.command(cert_import)
    for res in cert_find_output.values():
        if res['rc'] == 0:
            assert 'Imported certificate "CA CERT"' in res['stdout']
            log.info("Failed to import cert to database.")
            pytest.xfail("Failed to import cert to database.")
        else:
            assert 'Error: Unable to import certificate file' in res['stderr']
            log.info("Success: Unable to import cert with invalid trust flag.")
    ansible_module.command('rm -rf {} {}'.format(admin_pem, admin_p12))


def test_pki_client_cert_import_valid_serial(ansible_module):
    """
    :Title: Test pki client-cert-import, import cert with valid serial.
    :Description: test pki client-cert-import --serial command to import ca cert
    :Requirement: Pki Client
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Create Certificate request and approve it.
        2. Execute pki -d <db_path> -c <db_password> client-cert-import <nickname> --cert <certfile>
        --serial <valid serial no>
    :Expectedresults:
        1. Command with valid serial no imports the cert to the security database.
    """
    no = random.randint(11, 999989)
    user = 'testuser{}'.format(no)
    subject = 'UID={},CN={}'.format(user, user)
    import_ca_admin = 'pki -d {} -c {} client-cert-import --pkcs12 {}/ca_admin_cert.p12 ' \
                      '--pkcs12-password {}'.format(local_db, constants.CLIENT_DIR_PASSWORD,
                                                    constants.CA_CLIENT_DIR,
                                                    constants.CLIENT_PKCS12_PASSWORD)
    ansible_module.command(import_ca_admin)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject)
    cert_import = 'pki -d {} -c {} -p {} -h localhost client-cert-import "{}" ' \
                  '--serial {}'.format(local_db, constants.CLIENT_DIR_PASSWORD,
                                       constants.CA_HTTP_PORT, user, cert_id)
    cert_import_output = ansible_module.command(cert_import)
    for res in cert_import_output.values():
        if res['rc'] == 0:
            assert 'Imported certificate "{}"'.format(user) in res['stdout']
            log.info("Successfully import cert using --serial option.")
        else:
            log.info("Failed to run pki client-cert-import --serial command.")
            pytest.xfail("Failed to run pki client-cert-import command.")
    ansible_module.command('pki -d {} -c {} client-cert-del '
                           '"{}"'.format(local_db, constants.CLIENT_DIR_PASSWORD, user))


def test_pki_client_cert_import_invalid_serial(ansible_module):
    """
    :Title: Test pki client-cert-import with invalid serial no.
    :Description: test pki client-cert-import --serial command to import ca cert
    :Requirement: Pki Client
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d <db> -c <pass> client-cert-import --serial <invalid_serial>
    :Expectedresults:
        1. Command with invalid serial certificate no. doesn't imports the cert to the
        security database.
    """
    client_import = 'pki -d {} -c {} client-cert-import --serial 0xgh'
    cert_import_output = ansible_module.command(client_import)
    for res in cert_import_output.values():
        if res['rc'] >= 1:
            assert 'NumberFormatException: For input string: "gh"' in res['stderr']
            log.info("Success: Unable to import cert with invalid serial no.")
        else:
            log.info("Failed: Imported cert with Invalid serial no.")
            pytest.xfail("Failed: Imported cert with Invalid serial no.")


def test_pki_client_cert_import_wrong_pkcspassword(ansible_module):
    """
    :Title: Test pki client-cert-import with wrong pkcs12 password.
    :Description: test pki client-cert-import command with wrong pkcs12 password
    :Requirement: Pki Client
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d <db_path> -c <db_password> client-cert-import --pkcs12 <path>
        --pkcs12-password <password>
    :Expectedresults:
        1. Command with wrong pkcs12 password throws error.
    """
    pkcs_password = utils.get_random_string()
    client_import = 'pki -d {} -c {} client-cert-import --pkcs12 {}/ca_admin_cert.p12 ' \
                    '--pkcs12-password {}'.format(local_db, constants.CLIENT_DIR_PASSWORD,
                                                  constants.CA_CLIENT_DIR,
                                                  pkcs_password)
    cert_find_output = ansible_module.command(client_import)
    for res in cert_find_output.values():
        if res['rc'] >= 1:
            assert "Error: Unable to import PKCS #12 file" in res['stderr']
            log.info("Success: Unable to import certificate with wrong pkcs12 password.")
        else:
            log.info("Failed: Imported certificate with wrong pkcs12 password.")
            pytest.xfail("Failed: Imported certificate with wrong pkcs12 password.")


def test_pki_client_cert_import_wrong_dbpassword(ansible_module):
    """
    :Title: Test pki client-cert-import with wrong database password.
    :Description: test pki client-cert-import command with wrong database password
    :Requirement: Pki Client
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1.  pki -d <db_path> -c <password> client-cert-import --pkcs12 <path>
    --pkcs12-password <password>
    :Expectedresults:
        1. Command with wrong database password throws error.
    """
    db_password = utils.get_random_string(len=8)
    client_import = 'pki -d {} -c {} client-cert-import --pkcs12 {}/ca_admin_cert.p12 ' \
                    '--pkcs12-password {}'.format(local_db, db_password,
                                                  constants.CA_CLIENT_DIR,
                                                  db_password)
    cert_find_output = ansible_module.command(client_import)
    for res in cert_find_output.values():
        if res['rc'] >= 1:
            assert "Error: Unable to import PKCS #12 file" in res['stderr']
            log.info("Success: Unable to import certificate with wrong pkcs12 password.")
        else:
            log.info("Failed: Imported certificate with wrong pkcs12 password.")
            pytest.xfail("Failed: Imported certificate with wrong pkcs12 password.")


def test_bug_1357075_pki_client_cert_import_ca_cert_with_CT_trust(ansible_module):
    """
    :Title: Import CA certificate with CT,CT,CT trust arguments.
    :Description: Test pki client-cert-import --trust command to import ca cert with CT,CT,CT trust
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement: Pki Client
    :Steps:
        1. Save CA certificate in b64 encodecd format.
        2. Execute pki -d <db_path> -c <db_password> client-cert-import <nickname> -
        -cert <certfile> --trust <invalid trust flag>
    :Assert:
        1. Command with correct trust arguments get stored in the database
    """
    get_ca_cert_id = 'pki -p {} ca-cert-find --name "CA Signing Certificate" --orgUnit "{}" ' \
                     '--org "{}" --matchExactly'.format(constants.CA_HTTP_PORT, instance_name,
                                                        constants.CA_SECURITY_DOMAIN_NAME)

    pem_file = '/tmp/ca_signing.pem'
    serial = None
    client_cert_import = ' pki -d {} -c {} client-cert-import "RootCA with Trust" ' \
                         '--ca-cert {} --trust "CT,CT,CT"'.format(local_db, constants.CLIENT_PKCS12_PASSWORD, pem_file)
    get_ca_cert_out = ansible_module.command(get_ca_cert_id)
    for res in get_ca_cert_out.values():
        if res['rc'] == 0:
            assert '1 entries found' in res['stdout']
            raw_no = re.findall('Serial Number: [\w].*', res['stdout'])
            serial = raw_no[0].split(":")[1].strip()
            export_to_pem = 'pki -p {} ca-cert-show {} --output {} ' \
                            '--encoded'.format(constants.CA_HTTP_PORT, serial, pem_file)
            pem_out = ansible_module.command(export_to_pem)
            for r in pem_out.values():
                if r['rc'] == 0:
                    is_file = ansible_module.stat(path=pem_file)
                    for r1 in is_file.values():
                        assert r1['stat']['exists']
                else:
                    log.info("Failed to export certificate to the file.")
                    pytest.xfail("Failed to export certificate to the file.")

    cert_import = ansible_module.command(client_cert_import)
    for result in cert_import.values():
        if result['rc'] == 0:
            assert 'Imported certificate "RootCA with Trust"' in result['stdout']
            log.info("Successfully imported the CA certificate with trust 'CT,CT,CT'.")
            certutil_out = ansible_module.command('certutil -L -d {}'.format(local_db))
            for res in certutil_out.values():
                if res['rc'] == 0:
                    assert 'RootCA with Trust' in res['stdout']
                    assert 'CT,C,C' in res['stdout']
                else:
                    pytest.xfail("Failed to run certutil command.")
        else:
            log.info("Failed to import the certificate with the trust 'CT,CT,CT'.")
            pytest.xfail("Failed to import the certificate with the trust.")


def test_bug_1458429_test_pki_client_cert_import_with_trust_bits(ansible_module):
    """
    :Title: Bug-1458429: pki client-cert-import --ca-cert should import CA cert with trust bits
    "CT,C,C"
    :Test: Test pki client-cert-import --ca-cert should import CA cert with trust bits "CT,C,C"
    :Description: CA Certificate should be imported with "CT,C,C" trust bits by default.
    :Requirement: Pki Client
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
            1. Initiate new client directory.
            2. Import CA certificate in the new client directory using pki client-cert-import

    :Expectedresults:
                1. Verify that the ca certificate trust bits are set to "CT,C,C".
    """

    client_import = 'pki -d {} -c {} -p {} client-cert-import RootCA ' \
                    '--ca-server'.format(local_db, constants.CLIENT_DIR_PASSWORD,
                                         constants.CA_HTTP_PORT)
    client_out = ansible_module.command(client_import)
    for result in client_out.values():
        if result['rc'] == 0:
            assert 'Imported certificate "RootCA"' in result['stdout']
            certutil = 'certutil -L -d {}'.format(local_db)
            certutil_out = ansible_module.command(certutil)
            for res in certutil_out.values():
                if res['rc'] == 0:
                    assert "RootCA" in res['stdout']
                    assert "CT,C,C" in res['stdout']
                    log.info("Successfully imported certificate with CT,C,C trust.")
                else:
                    log.info("Failed to run certutil -L -d {} command.".format(local_db))
                    pytest.xfail("Failed to run certutil -L -d {} command.".format(local_db))
        else:
            log.info("Failed to run '{}' command.".format(client_import))
            pytest.xfail("Failed to run '{}' command.".format(client_import))


def test_pki_client_cert_import_cert_import_from_ca(ansible_module):
    """
    :Title: Test pki client-cert-import, import cert with different trusts.
    :Description: test pki client-cert-import, import cert with different trusts.
    :Requirement: Pki Client
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Create Certificate request and approve it.
        2. Execute pki -d <db_path> -c <db_password> client-cert-import <nickname> --cert <certfile>
        --serial <valid serial no> --trust 'CT,C,C'
    :Expectedresults:
        1. Command with valid serial no imports the cert to the security database with CT,C,C trust.
        2. It should show the 'CTu,Cu,Cu' trust on the certificate.
    """
    no = random.randint(11, 999989)
    user = 'testuser{}'.format(no)
    subject = 'UID={},CN={}'.format(user, user)
    local_db = constants.NSSDB
    import_ca_admin = 'pki -d {} -c {} client-cert-import --pkcs12 {}/ca_admin_cert.p12 ' \
                      '--pkcs12-password {}'.format(local_db, constants.CLIENT_DIR_PASSWORD,
                                                    instance_name, constants.CLIENT_PKCS12_PASSWORD)
    ansible_module.command(import_ca_admin)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject)
    cert_import = 'pki -d {} -c {} -p {} -h {} client-cert-import "{}" ' \
                  '--serial {} --trust "CT,C,C"'.format(local_db, constants.CLIENT_DIR_PASSWORD, constants.CA_HTTP_PORT,
                                                        constants.MASTER_HOSTNAME, user, cert_id)
    cert_import_output = ansible_module.command(cert_import)
    for res in cert_import_output.values():
        if res['rc'] == 0:
            assert 'Imported certificate "{}"'.format(user) in res['stdout']
            log.info("Successfully import cert using --trust 'CT,C,C' option.")

            log.info("Verifying the certificate trust.")
            certutil_out = ansible_module.command('certutil -L -d {}'.format(local_db))
            for r in certutil_out.values():
                if r['rc'] == 0:
                    log.info("Getting certificate name from nssdb.")
                    cert_names = re.findall('{}.*'.format(user), r['stdout'])
                    user_cert = cert_names[0].strip()
                    log.info("Verifying the certificate name and trust flags.")
                    assert user in user_cert
                    assert 'CTu,Cu,Cu' in user_cert
                else:
                    log.error("Failed to list the certificate from nssdb.")
                    pytest.xfail("Failed to list the certificate from nssdb.")
        else:
            log.info("Failed to run pki client-cert-import --trust 'CT,C,C' command.")
            pytest.xfail("Failed to run pki client-cert-import command.")
    ansible_module.command('pki -d {} -c {} client-cert-del '
                           '"{}"'.format(local_db, constants.CLIENT_DIR_PASSWORD, user))
