#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI CA-USER-CERT CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki user commands needs to be tested:
#   pki ca-user-cert
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
import sys
import re
import pytest

from pki.testlib.common.utils import UserOperations

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

userop = UserOperations(nssdb=constants.NSSDB)
log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
TOPOLOGY = constants.CA_INSTANCE_NAME.split("-")[1]

pki_cmd = "ca-user-cert-add"
if TOPOLOGY != '01':
    CA_SUBJECT = 'CN=CA Signing Certificate,OU={},O={}'.format(constants.CA_INSTANCE_NAME,
                                                               constants.CA_SECURITY_DOMAIN_NAME)
else:
    CA_SUBJECT = 'CN=CA Signing Certificate,OU={},O={}'.format('pki-tomcat',
                                                               constants.CA_SECURITY_DOMAIN_NAME)

basic_pki_cmd = 'pki -d {} -c {} -p {} -P {} -n "{}" '.format(constants.NSSDB,
                                                        constants.CLIENT_DIR_PASSWORD,
                                                        constants.CA_HTTPS_PORT,
                                                        constants.PROTOCOL_SECURE,
                                                        constants.CA_ADMIN_NICK)

group_del = 'pki -d {} -c {} -p {} -n "{}" ' \
            'ca-group-del '.format(constants.NSSDB, constants.CLIENT_DIR_PASSWORD,
                                   constants.CA_HTTPS_PORT, constants.CA_ADMIN_NICK)

client_cert_del = 'pki -d {} -c {} client-cert-del '.format(constants.NSSDB,
                                                            constants.CLIENT_DIR_PASSWORD)


@pytest.mark.parametrize('args', ['--help', '', 'asdfa'])
def test_pki_ca_user_cert_add_help_command(ansible_module, args):
    """
    :Title: Test pki ca-user-cert-add --help command
    :Description: Command should show pki ca-user-cert-add --help options and uses.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. run pki ca-user-cert-add --help
        2. run pki ca-user-cert-add ''
        3. run pki ca-user-cert-add asdfa
    :ExpectedResults:
        1. Verify whether pki ca-user-cert-add --help should show the options and uses messages.
        2. It should throw an error.
        3. It should throw an error.
    :Automated: Yes
    """
    user_cert_add_help = 'pki ca-user-cert-add {}'.format(args)
    cmd_out = ansible_module.command(user_cert_add_help)
    for result in cmd_out.values():
        if args == '--help':
            assert "ca-user-cert-add <User ID> [OPTIONS...]" in result['stdout']
            assert re.search("--input <file>\s+Input file", result['stdout'])
            assert re.search("--serial <serial number>\s+Serial number of certificate in CA", result['stdout'])
            assert re.search("--help\s+Show help message", result['stdout'])
            log.info('Successfully ran: {}'.format(result['cmd']))
        elif args == '':
            assert 'No User ID specified.' in result['stderr']
            log.info('Successfully ran: {}'.format(result['cmd']))
        elif args == 'asdfa':
            assert 'Missing input file or serial number.' in result['stderr']
            log.info('Successfully ran: {}'.format(result['cmd']))
        else:
            log.error('Failed to run: {}'.format(result['cmd']))
            pytest.fail('Failed to ran: {}'.format(result['cmd']))


@pytest.mark.parametrize('algo,keysize', [('rsa', '2048'), ('ec', 'nistp256')])
@pytest.mark.parametrize('r_type', ['crmf', 'pkcs10'])
def test_pki_ca_user_cert_add_cli_add_cert_to_user(ansible_module, algo, keysize, r_type):
    """
    :Title: Test pki ca-user-cert-add one cert to the user should succeed.
    :Description: Command should show pki ca-user-cert-add add the pkcs10 and crmf certificate to
    the user.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add User
        2. Generate the certificate.
        3. Add certificate to the user.
    :ExpectedResults:
        1. Verify whether pki ca-user-cert-add the certificate to the user.
    :Automated: Yes
    """
    user = 'tuser1'
    fullName = 'TestUser1'
    subject = "UID={},CN={}".format(user, fullName)
    cert_ids = []
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    cert_id = None
    if algo == 'rsa':
        cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                     request_type=r_type, algo=algo,
                                                     keysize=keysize, profile='caUserCert')
    elif algo == 'ec':
        cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                     request_type=r_type, algo=algo,
                                                     curve=keysize, profile='caECUserCert')
    if cert_id:
        cert_ids.append(cert_id)
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)

        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTPS_PORT,
                                     protocol='https',
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='{} --serial {}'.format(user, cert_id))

        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Added certificate "{}"'.format(cert_subject) in result['stdout']
                assert 'Cert ID: {}'.format(cert_subject) in result['stdout']
                assert 'Version: 2' in result['stdout']
                assert 'Serial Number: {}'.format(cert_id) in result['stdout']
                assert 'Issuer: {}'.format(CA_SUBJECT) in result['stdout']
                assert 'Subject: {}'.format(subject) in result['stdout']
                log.info("Successfully run: {}".format(result['cmd']))
            else:
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()
    else:
        log.error("Failed to generate the certificate.")
        pytest.fail()

    cmd_out = ansible_module.pki(cli='ca-user-cert-find',
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTPS_PORT,
                                 protocol='https',
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(user))
    for result in cmd_out.values():
        if result['rc'] == 0:
            for cid in cert_ids:
                cert_subject = "2;{};{};{}".format(int(cid, 16), CA_SUBJECT, subject)
                assert 'Cert ID: {}'.format(cert_subject) in result['stdout']
                assert 'Version: 2' in result['stdout']
                assert 'Serial Number: {}'.format(cid) in result['stdout']
                assert 'Issuer: {}'.format(CA_SUBJECT) in result['stdout']
                assert 'Subject: {}'.format(subject) in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()
    userop.remove_user(ansible_module, user)


@pytest.mark.parametrize('algo,keysize', [('rsa', '2048'), ('ec', 'nistp256')])
@pytest.mark.parametrize('r_type', ['crmf', 'pkcs10'])
def test_pki_ca_user_cert_add_using_input_argument(ansible_module, algo, keysize, r_type):
    """
    :Title: Test pki ca-user-cert-add one cert to the user using --input.
    :Description: Command should show pki ca-user-cert-add add the pkcs10 and crmf certificate to
    the user.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add User
        2. Generate the certificate.
        3. Add certificate to the user using --input
    :ExpectedResults:
        1. Verify whether pki ca-user-cert-add the certificate to the user.
    :Automated: Yes
    """
    user = 'tuser1'
    fullName = 'TestUser1'
    subject = "UID={},CN={}".format(user, fullName)

    cert_ids = []
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    cert_id = None
    if algo == 'rsa':
        cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                     request_type=r_type, algo=algo,
                                                     keysize=keysize, profile='caUserCert')
    elif algo == 'ec':
        cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                     request_type=r_type, algo=algo,
                                                     curve=keysize, profile='caECUserCert')
    if cert_id:
        cert_ids.append(cert_id)
        cert_file = '/tmp/certificate_{}.pem'.format(cert_id)
        export_out = ansible_module.command(basic_pki_cmd + "ca-cert-show {} "
                                                            "--output {}".format(cert_id,
                                                                                 cert_file))
        for res in export_out.values():
            assert res['rc'] == 0

        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)

        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTPS_PORT,
                                     protocol='https',
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='{} --input {}'.format(user, cert_file))

        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Added certificate "{}"'.format(cert_subject) in result['stdout']
                assert 'Cert ID: {}'.format(cert_subject) in result['stdout']
                assert 'Version: 2' in result['stdout']
                assert 'Serial Number: {}'.format(cert_id) in result['stdout']
                assert 'Issuer: {}'.format(CA_SUBJECT) in result['stdout']
                assert 'Subject: {}'.format(subject) in result['stdout']
                log.info("Successfully run: {}".format(result['cmd']))
            else:
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()
    else:
        log.error("Failed to generate the certificate.")
        pytest.fail()

    cmd_out = ansible_module.pki(cli='ca-user-cert-find',
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTPS_PORT,
                                 protocol='https',
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(user))
    for result in cmd_out.values():
        if result['rc'] == 0:
            for cid in cert_ids:
                cert_subject = "2;{};{};{}".format(int(cid, 16), CA_SUBJECT, subject)
                assert 'Cert ID: {}'.format(cert_subject) in result['stdout']
                assert 'Version: 2' in result['stdout']
                assert 'Serial Number: {}'.format(cid) in result['stdout']
                assert 'Issuer: {}'.format(CA_SUBJECT) in result['stdout']
                assert 'Subject: {}'.format(subject) in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_cert_add_multiple_cert_to_user(ansible_module):
    """
    :Title: Test pki ca-user-cert-add, add multiple cert to one user should succeed.
    :Description: Command should show pki ca-user-cert-add, add multiple cert to one user should succeed.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add user
        2. Issue 2 certificates.
        3. Add certificates to the user.
    :ExpectedResults:
        1. Verify whether pki ca-user-cert-add, add multiple cert to one user should succeed.
    :Automated: Yes
    """
    user = 'tuser2'
    fullName = 'TestUser2'
    subject = "UID={},CN={}".format(user, fullName)
    cert_ids = []
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    for i in range(2):
        for cert_type in ['pkcs10', 'crmf']:
            cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                         request_type=cert_type, algo='rsa',
                                                         keysize='2048', profile='caUserCert')
            if cert_id:
                cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
                cert_ids.append(cert_id)
                cmd_out = ansible_module.pki(cli=pki_cmd,
                                             nssdb=constants.NSSDB,
                                             dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                             port=constants.CA_HTTPS_PORT,
                                             protocol='https',
                                             hostname=constants.MASTER_HOSTNAME,
                                             certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                             extra_args='{} --serial {}'.format(user, cert_id))

                for result in cmd_out.values():
                    if result['rc'] == 0:
                        assert 'Added certificate "{}"'.format(cert_subject) in result['stdout']
                        assert 'Cert ID: {}'.format(cert_subject) in result['stdout']
                        assert 'Version: 2' in result['stdout']
                        assert 'Serial Number: {}'.format(cert_id) in result['stdout']
                        assert 'Issuer: {}'.format(CA_SUBJECT) in result['stdout']
                        assert 'Subject: {}'.format(subject) in result['stdout']
                        log.info("Successfully run: {}".format(result['cmd']))
                    else:
                        log.error("Failed to run: {}".format(result['cmd']))
                        pytest.fail()
            else:
                log.error("Failed to generate the certificate.")
                pytest.fail()
    cmd_out = ansible_module.pki(cli='ca-user-cert-find',
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTPS_PORT,
                                 protocol='https',
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(user))
    for result in cmd_out.values():
        if result['rc'] == 0:
            for cid in cert_ids:
                cert_subject = "2;{};{};{}".format(int(cid, 16), CA_SUBJECT, subject)
                assert 'Cert ID: {}'.format(cert_subject) in result['stdout']
                assert 'Version: 2' in result['stdout']
                assert 'Serial Number: {}'.format(cid) in result['stdout']
                assert 'Issuer: {}'.format(CA_SUBJECT) in result['stdout']
                assert 'Subject: {}'.format(subject) in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_cert_add_expired_cert_to_user(ansible_module):
    """
    :Title: Test pki ca-user-cert-add, adding expired cert to the user should fail.
    :Description: Command should show pki ca-user-cert-add, add expired cert to the user should fail.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add uesr, Issue certificate to user, which will expire in mins.
        2. Add the Expired certificate to the user.
    :ExpectedResults:
        1. Expired certificate should get added to the user.
    :Automated: Yes
    """
    user = 'testuserE'
    fullName = 'testuserE'
    cert_ids = []
    subject = 'UID={},CN={}'.format(user, fullName)
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    for cert_type in ['pkcs10', 'crmf']:
        cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                     request_type=cert_type, algo='rsa',
                                                     keysize='2048', profile='caAgentFoobar')
        if cert_id:
            cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
            cert_ids.append(cert_id)
            cmd_out = ansible_module.pki(cli=pki_cmd,
                                         nssdb=constants.NSSDB,
                                         dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                         port=constants.CA_HTTPS_PORT,
                                         protocol='https',
                                         hostname=constants.MASTER_HOSTNAME,
                                         certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                         extra_args='{} --serial {}'.format(user, cert_id))

            for result in cmd_out.values():
                if result['rc'] == 0:
                    assert 'Added certificate "{}"'.format(cert_subject) in result['stdout']
                    assert 'Cert ID: {}'.format(cert_subject) in result['stdout']
                    assert 'Version: 2' in result['stdout']
                    assert 'Serial Number: {}'.format(cert_id) in result['stdout']
                    assert 'Issuer: {}'.format(CA_SUBJECT) in result['stdout']
                    assert 'Subject: {}'.format(subject) in result['stdout']
                    log.info("Successfully run: {}".format(result['cmd']))
                else:
                    log.error("Failed to run: {}".format(result['cmd']))
                    pytest.fail()
        else:
            log.error("Failed to generate the certificate.")
            pytest.fail()
    cmd_out = ansible_module.pki(cli='ca-user-cert-find',
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTPS_PORT,
                                 protocol='https',
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(user))
    for result in cmd_out.values():
        if result['rc'] == 0:
            for cid in cert_ids:
                cert_subject = "2;{};{};{}".format(int(cid, 16), CA_SUBJECT, subject)
                assert 'Cert ID: {}'.format(cert_subject) in result['stdout']
                assert 'Version: 2' in result['stdout']
                assert 'Serial Number: {}'.format(cid) in result['stdout']
                assert 'Issuer: {}'.format(CA_SUBJECT) in result['stdout']
                assert 'Subject: {}'.format(subject) in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_cert_add_revoked_cert_to_user(ansible_module):
    """
    :Title: Test pki ca-user-cert-add, add revoked cert to user should succeed.
    :Description: Command should show pki ca-user-cert-add, add revoked cert to user should succeed.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add uesr, Issue certificate to user, Revoke the certificate.
        2. Add the Revoked certificate to the user.
    :ExpectedResults:
        1. Verify whether pki ca-user-cert-add, add revoked cert to user should succeed.
    :Automated: Yes
    """
    user = 'tuser4'
    fullName = 'Test {}'.format(user)
    cert_ids = []
    subject = 'UID={},CN={}'.format(user, fullName)
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    for cert_type in ['pkcs10', 'crmf']:
        cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                     request_type=cert_type, algo='rsa',
                                                     keysize='2048', revoke=True)
        if cert_id:
            cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
            cert_ids.append(cert_id)
            cmd_out = ansible_module.pki(cli=pki_cmd,
                                         nssdb=constants.NSSDB,
                                         dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                         port=constants.CA_HTTPS_PORT,
                                         protocol='https',
                                         hostname=constants.MASTER_HOSTNAME,
                                         certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                         extra_args='{} --serial {}'.format(user, cert_id))

            for result in cmd_out.values():
                if result['rc'] == 0:
                    assert 'Added certificate "{}"'.format(cert_subject) in result['stdout']
                    assert 'Cert ID: {}'.format(cert_subject) in result['stdout']
                    assert 'Version: 2' in result['stdout']
                    assert 'Serial Number: {}'.format(cert_id) in result['stdout']
                    assert 'Issuer: {}'.format(CA_SUBJECT) in result['stdout']
                    assert 'Subject: {}'.format(subject) in result['stdout']
                    log.info("Successfully run: {}".format(result['cmd']))
                else:
                    log.error("Failed to run: {}".format(result['cmd']))
                    pytest.fail()
        else:
            log.error("Failed to generate the certificate.")
            pytest.fail()
    cmd_out = ansible_module.pki(cli='ca-user-cert-find',
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTPS_PORT,
                                 protocol='https',
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(user))
    for result in cmd_out.values():
        if result['rc'] == 0:
            for cid in cert_ids:
                cert_subject = "2;{};{};{}".format(int(cid, 16), CA_SUBJECT, subject)
                assert 'Cert ID: {}'.format(cert_subject) in result['stdout']
                assert 'Version: 2' in result['stdout']
                assert 'Serial Number: {}'.format(cid) in result['stdout']
                assert 'Issuer: {}'.format(CA_SUBJECT) in result['stdout']
                assert 'Subject: {}'.format(subject) in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_cert_add_when_userid_missing(ansible_module):
    """
    :Title: Test adding cert to user should failed when userid is missing.
    :Description: Command should show pki ca-user-cert-add, add cert to user should failed when userid is missing.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. run pki ca-user-cert-add --serial cert_id without userid
    :ExpectedResults:
        1. Verify whether pki ca-user-cert-add, add cert to user should failed when userid is missing.
    :Automated: Yes
    """
    user = 'tuser5'
    fullName = 'Test {}'.format(user)
    subject = 'UID={},CN={}'.format(user, fullName)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', revoke=True)
    if cert_id:
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTPS_PORT,
                                     protocol='https',
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='--serial {}'.format(cert_id))

        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Added certificate "{}"'.format(cert_subject) in result['stdout']
                assert 'Cert ID: {}'.format(cert_subject) in result['stdout']
                assert 'Version: 2' in result['stdout']
                assert 'Serial Number: {}'.format(cert_id) in result['stdout']
                assert 'Issuer: {}'.format(CA_SUBJECT) in result['stdout']
                assert 'Subject: {}'.format(subject) in result['stdout']
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()
            else:
                assert 'No User ID specified' in result['stderr']
                log.info("Successfully run: {}".format(result['cmd']))

    else:
        log.error("Failed to generate the certificate.")
        pytest.fail()


def test_pki_ca_user_cert_add_when_input_parameter_missing(ansible_module):
    """
    :Title: Test pki ca-user-cert-add, add cert should fail when --input parameter is missing.
    :Description: Command should show pki ca-user-cert-add, add cert should fail when --input parameter is missing.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. pki ca-user-cert-add user
    :ExpectedResults:
        1. Command should fail when --input parameter is missing.
    :Automated: Yes
    """
    user = 'tuser6'
    fullName = 'Test {}'.format(user)
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTPS_PORT,
                                 protocol='https',
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(user))

    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added certificate' in result['stdout']
            assert 'Cert ID: ' in result['stdout']
            assert 'Version: 2' in result['stdout']
            assert 'Serial Number: ' in result['stdout']
            assert 'Issuer: {}'.format(CA_SUBJECT) in result['stdout']
            assert 'Subject:' in result['stdout']
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()
        else:
            assert 'Missing input file or serial number' in result['stderr']
            log.info("Successfully run: {}".format(result['cmd']))
    userop.remove_user(ansible_module, user)


@pytest.mark.parametrize('args', ['serial', 'input'])
def test_pki_ca_user_cert_add_when_input_args_missing(ansible_module, args):
    """
    :Title: Test adding cert should fail when argument for --input parameter is missing.
    :Description: Command should show pki ca-user-cert-add, add cert should fail when argument for
        --input parameter is missing.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
        :Steps:
        1. pki ca-user-cert-add user <userid> --input
        2. pki ca-user-cert-add user <userid> --serial
    :ExpectedResults:
        1. Command should fail when --input parameter is missing.
        2. Command should fail when --serial parameter is missing.
    :Automated: Yes
    """

    user = 'tuser7'
    fullName = 'Test {}'.format(user)

    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTPS_PORT,
                                 protocol='https',
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --{}'.format(user, args))

    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added certificate' in result['stdout']
            assert 'Cert ID: ' in result['stdout']
            assert 'Version: 2' in result['stdout']
            assert 'Serial Number: ' in result['stdout']
            assert 'Issuer: {}'.format(CA_SUBJECT) in result['stdout']
            assert 'Subject:' in result['stdout']
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()
        else:
            error = 'MissingArgumentException: Missing argument for option: {}'.format(args)
            assert error in result['stderr']
            log.info("Successfully run: {}".format(result['cmd']))
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_cert_add_when_cert_is_invalid(ansible_module):
    """
    :Title: Test pki ca-user-cert-add, add cert should fail when cert is invalid.
    :Description: Command should show pki ca-user-cert-add, add user should fail when cert is invalid.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add user, Issue certificate against user.
        2. Make changes in the certificate and make it bad.
        3. Add that certificate to the user.
    :ExpectedResults:
        1. Adding cert should fail when cert is invalid.
    :Automated: Yes
    """

    user = 'tuser8'
    fullName = 'Test {}'.format(user)
    subject = 'UID={},CN={}'.format(user, fullName)
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', revoke=True)
    if cert_id:
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
        cert_file = '/tmp/certificate_{}.pem'.format(cert_id)
        export_out = ansible_module.command(basic_pki_cmd + "ca-cert-show {} "
                                                            "--output {}".format(cert_id,
                                                                                 cert_file))
        for res in export_out.values():
            assert res['rc'] == 0
            ansible_module.replace(path=cert_file, regexp="-----BEGIN CERTIFICATE-----",
                                   replace="BEGIN CERTIFICATE--")
        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTPS_PORT,
                                     protocol='https',
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='{} --input {}'.format(user, cert_file))

        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Added certificate "{}"'.format(cert_subject) in result['stdout']
                assert 'Cert ID: {}'.format(cert_subject) in result['stdout']
                assert 'Version: 2' in result['stdout']
                assert 'Serial Number: {}'.format(cert_id) in result['stdout']
                assert 'Issuer: {}'.format(CA_SUBJECT) in result['stdout']
                assert 'Subject: {}'.format(subject) in result['stdout']
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()
            else:
                error = "PKIException: Unable to import user certificate from PKCS #7 data"
                assert error in result['stderr']
                log.info("Successfully run: {}".format(result['cmd']))

    else:
        log.error("Failed to generate the certificate.")
        pytest.fail()
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_cert_add_when_input_file_not_exists(ansible_module):
    """
    :Title: Test pki ca-user-cert-add, add cert should fail when input file does not exists.
    :Description: Command should show pki ca-user-cert-add, add cert should fail when input file does not exists.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. pki ca-user-cert-add --input <invalid_path>
    :ExpectedResults:
        1. Verify whether pki ca-user-cert-add, add cert should fail when input file does not exists.
    :Automated: Yes
    """
    user = 'tuser9'
    fullName = 'Test {}'.format(user)

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTPS_PORT,
                                 protocol='https',
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --input {}'.format(user, '/tmp/sdfsadf.pem'))

    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added certificate' in result['stdout']
            assert 'Cert ID: ' in result['stdout']
            assert 'Version: 2' in result['stdout']
            assert 'Serial Number: ' in result['stdout']
            assert 'Issuer: {}'.format(CA_SUBJECT) in result['stdout']
            assert 'Subject:' in result['stdout']
            pytest.fail()
        else:
            error = "NoSuchFileException: /tmp/sdfsadf.pem"
            assert error in result['stderr']
            log.info("Successfully run: {}".format(result['cmd']))


def test_pki_ca_user_cert_add_with_i18n_character(ansible_module):
    """
    :id: 21a1b0a4-5666-405a-bf4a-cfc0ae86691b
    :Title: Test pki ca-user-cert-add with i18n character
    :Description: Pki ca-user-cert-add with i18n character
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Add the i18n character user
        2. Issue the certificate request.
        3. Approve the certificate request.
    :Expectedresults:
        1. User should get added.
        2. Certificate request should be issued and submitted to the CA.
        3. Get the certificate id after the approval of the request id.
    :Automated: Yes
    """
    userid = 'ÖrjanÄke{}'.format(random.randint(1111, 9999999))
    subject = 'UID={},CN={}'.format(userid, userid)
    cert_req = ansible_module.pki(cli='client-cert-request',
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DIR_PASSWORD,
                                      port=constants.CA_HTTPS_PORT,
                                      protocol='https',
                                      certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                      extra_args='"{}"'.format(subject))
    for result in cert_req.values():
        if result['rc'] == 0:
            request_id_raw = re.findall('Request ID: [\w].*', result['stdout'])
            request_id = request_id_raw[0].split(":")[1].strip()
            assert 'Request ID: {}'.format(request_id) in result['stdout']
            assert 'Type: enrollment' in result['stdout']
            assert 'Request Status: pending' in result['stdout']
            assert 'Operation Result: success' in result['stdout']
            log.info("Successfully run '{}'".format(cert_req))
        else:
            log.error("Failed to run '{}'".format(cert_req))
            pytest.fail("Failed to run '{}'".format(cert_req))
    log.info("Generated certificate with Cert ID: {}".format(request_id))
    req_update = 'pki -d {} -c {} -n "{}" -p {} -P https ca-cert-request-review {}'.format(constants.NSSDB, constants.CLIENT_DATABASE_PASSWORD,
                                    constants.CA_ADMIN_NICK, constants.CA_HTTPS_PORT, request_id)
    log.info("Running: {}".format(req_update))
    update_prof = ansible_module.expect(
        command=req_update,
        responses={"Action \(approve/reject/cancel/update/validate/assign/unassign\): ": 'approve'})

    for result in update_prof.values():
        if result['rc'] == 0:
            assert 'Retrieved certificate request {}'.format(request_id) in result['stdout']
            assert 'Request ID: {}'.format(request_id) in result['stdout']
            assert 'Type: enrollment' in result['stdout']
            assert 'Request Status: complete' in result['stdout']
            assert 'Operation Result: success' in result['stdout']
            cert_id_raw = re.findall('Certificate ID: [\w].*', result['stdout'])
            cert_id = cert_id_raw[0].split(":")[1].strip()
        else:
            log.error("Failed to retrieve the certificate request in file.")
            pytest.fail()

    cmd_out = ansible_module.pki(cli='ca-user-add',
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTPS_PORT,
                                 protocol='https',
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='"{}" --fullName "{}"'.format(userid, userid))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added user "{}"'.format(userid) in result['stdout'].encode('utf-8')
            assert 'User ID: {}'.format(userid) in result['stdout'].encode('utf-8')
            assert 'Full name: {}'.format(userid) in result['stdout'].encode('utf-8')
            log.info('Successfully ran : {}'.format(result['cmd'].encode('utf-8')))
        else:
            assert result['rc'] >= 1
            log.info('Failed to run: {}'.format(result['cmd']))
            pytest.fail()

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTPS_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 protocol='https',
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='"{}" --serial {}'.format(userid, cert_id))

    for result in cmd_out.values():
        if result['rc'] == 0:
            cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
            assert 'Cert ID: {}'.format(cert_subject) in result['stdout'].encode('utf-8')
            assert 'Version: 2' in result['stdout'].encode('utf-8')
            assert 'Serial Number: {}'.format(cert_id) in result['stdout'].encode('utf-8')
            assert 'Version: 2' in result['stdout'].encode('utf-8')
            assert 'Serial Number: {}'.format(cert_id) in result['stdout'].encode('utf-8')
            assert 'Issuer: {}'.format(CA_SUBJECT) in result['stdout'].encode('utf-8')
            assert 'Subject: {}'.format(subject) in result['stdout'].encode('utf-8')
            log.info("Successfully run: {}".format(result['cmd'].encode('utf-8')))
        else:
            log.error("Failed to run: {}".format(result['cmd'].encode('utf-8')))
            log.error(result['stdout'].encode('utf-8'))
            log.error(result['stderr'].encode('utf-8'))
            pytest.fail()

    cmd_out = ansible_module.pki(cli='ca-user-cert-find',
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTPS_PORT,
                                 protocol='https',
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='"{}"'.format(userid))

    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Cert ID: {}'.format(cert_subject) in result['stdout'].encode('utf-8')
            assert 'Version: 2' in result['stdout']
            assert 'Serial Number: {}'.format(cert_id) in result['stdout'].encode('utf-8')
            assert 'Issuer: {}'.format(CA_SUBJECT) in result['stdout']
            assert 'Subject: {}'.format(subject) in result['stdout'].encode('utf-8')
            log.info("Successfully run: {}".format(result['cmd'].encode('utf-8')))
        else:
            log.error("Failed to run: {}".format(result['cmd'].encode('utf-8')))
            pytest.fail()

    cmd_out = ansible_module.pki(cli='ca-user-cert-show',
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTPS_PORT,
                                 protocol='https',
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='"{}" "{}"'.format(userid, cert_subject))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Cert ID:' in result['stdout']
            assert 'Version: 2' in result['stdout']
            assert 'Serial Number: {}'.format(cert_id) in result['stdout'].encode('utf-8')
            assert 'Issuer:' in result['stdout']
            assert 'Subject:' in result['stdout']
            log.info("Successfully run: {}".format(result['cmd'].encode('utf-8')))
        else:
            log.error("Failed to run: {}".format(result['cmd'].encode('utf-8')))
            pytest.fail()

    t_cmd_out = ansible_module.pki(cli='ca-user-cert-del',
                                   nssdb=constants.NSSDB,
                                   dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                   port=constants.CA_HTTPS_PORT,
                                   protocol='https',
                                   hostname=constants.MASTER_HOSTNAME,
                                   certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                   extra_args='"{}" "{}"'.format(userid, cert_subject))

    for result in t_cmd_out.values():
        if result['rc'] == 0:
            assert 'Deleted certificate "{}"'.format(cert_subject) in result['stdout'].encode('utf-8')
            log.info('Successfully Ran: {}'.format(result['cmd'].encode('utf-8')))
        else:
            assert result['rc'] >= 1
            log.error(result['stdout'].encode('utf-8'))
            log.error(result['stderr'].encode('utf-8'))
            pytest.fail()

    cmd_out = ansible_module.pki(cli='ca-user-del',
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTPS_PORT,
                                 protocol='https',
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='"{}"'.format(userid))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Deleted user "{}"'.format(userid) in result['stdout'].encode('utf-8')
            log.info('Successfully ran : {}'.format(result['cmd'].encode('utf-8')))
        else:
            assert result['rc'] >= 1
            log.info('Failed to run: {}'.format(result['cmd'].encode('utf-8')))
            pytest.fail()


@pytest.mark.parametrize("user_type", ['Auditors', 'Certificate Manager Agents',
                                       'Registration Manager Agents', 'Subsystem Group',
                                       'Security Domain Administrators', 'ClonedSubsystems',
                                       'Trusted Managers'])
def test_pki_ca_user_cert_add_user_to_different_group(ansible_module, user_type):
    """
    :Title: Test pki ca-user-cert-add, add cert to user of type 'Auditors'
    :Description: Command should show pki ca-user-cert-add, add cert to user of type 'Auditors'
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add user with type Auditors, add certificate to user.
        2. Add user with type Certificate Manager Agents, add certificate to user.
        3. Add user with type Registration Manager Agents, add certificate to user.
        4. Add user with type Subsystem Group, add certificate to user.
        5. Add user with type Security Domain Administrators, add certificate to user.
        6. Add user with type ClonedSubsystems, add certificate to user.
        7. Add user with type Trusted Managers, add certificate to user.
    :ExpectedResults:
        1. Certificate shoud get added to the all types of the users.
    :Automated: Yes
    """
    user = 'tuser11'
    fullName = 'Test {}'.format(user)
    subject = "UID={},CN={}".format(user, fullName)
    cert_ids = []
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName, type=user_type)

    for cert_type in ['pkcs10', 'crmf']:
        cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                     request_type=cert_type, algo='rsa',
                                                     keysize='2048', profile='caUserCert')
        if cert_id:
            cert_ids.append(cert_id)
            cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)

            cmd_out = ansible_module.pki(cli=pki_cmd,
                                         nssdb=constants.NSSDB,
                                         dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                         port=constants.CA_HTTPS_PORT,
                                         protocol='https',
                                         hostname=constants.MASTER_HOSTNAME,
                                         certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                         extra_args='{} --serial {}'.format(user, cert_id))

            for result in cmd_out.values():
                if result['rc'] == 0:
                    assert 'Added certificate "{}"'.format(cert_subject) in result['stdout']
                    assert 'Cert ID: {}'.format(cert_subject) in result['stdout']
                    assert 'Version: 2' in result['stdout']
                    assert 'Serial Number: {}'.format(cert_id) in result['stdout']
                    assert 'Issuer: {}'.format(CA_SUBJECT) in result['stdout']
                    assert 'Subject: {}'.format(subject) in result['stdout']
                    log.info("Successfully run: {}".format(result['cmd']))
                else:
                    log.error("Failed to run: {}".format(result['cmd']))
                    pytest.fail()
        else:
            log.error("Failed to generate the certificate.")
            pytest.fail()

    cmd_out = ansible_module.pki(cli='ca-user-cert-find',
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTPS_PORT,
                                 protocol='https',
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(user))
    for result in cmd_out.values():
        if result['rc'] == 0:
            for cid in cert_ids:
                cert_subject = "2;{};{};{}".format(int(cid, 16), CA_SUBJECT, subject)
                assert 'Cert ID: {}'.format(cert_subject) in result['stdout']
                assert 'Version: 2' in result['stdout']
                assert 'Serial Number: {}'.format(cid) in result['stdout']
                assert 'Issuer: {}'.format(CA_SUBJECT) in result['stdout']
                assert 'Subject: {}'.format(subject) in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_cert_add_to_admin_user_use_an_admin_user(ansible_module):
    """
    :Title: Test add admin user, add cert to admin user, add user as an admin user.
    :Description: Command should show pki ca-user-cert-add, add admin user, add cert to admin 
    user, add user as an admin user.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add adminuser, add it to the Administrator group.
        2. Issue, add certificate to the adminuser and import it to client database.
        3. Add certificate to the user using adminuser cert.
    :ExpectedResults:
        1. Certificate should get added to the user using adminuser cert.
    :Automated: Yes
    """
    adminuser = 'adminuser'
    adminuser1 = 'adminuser1'

    fullName = 'Admin User'
    subject = 'UID={},CN={}'.format(adminuser, fullName)
    userop.add_user(ansible_module, 'add', userid=adminuser, user_name=fullName)

    add_group = ansible_module.command(basic_pki_cmd + " group-member-add "
                                                       "Administrators {}".format(adminuser))
    for res in add_group.values():
        assert res['rc'] == 0

    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')
    if cert_id:
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)

        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTPS_PORT,
                                     protocol='https',
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='{} --serial {}'.format(adminuser, cert_id))

        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Added certificate "{}"'.format(cert_subject) in result['stdout']
                assert 'Cert ID: {}'.format(cert_subject) in result['stdout']
                assert 'Version: 2' in result['stdout']
                assert 'Serial Number: {}'.format(cert_id) in result['stdout']
                assert 'Issuer: {}'.format(CA_SUBJECT) in result['stdout']
                assert 'Subject: {}'.format(subject) in result['stdout']
                log.info("Successfully run: {}".format(result['cmd']))
            else:
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()

        import_cert = ansible_module.command(basic_pki_cmd + " client-cert-import {} "
                                                             "--serial {}".format(adminuser, cert_id))
        for result in import_cert.values():
            if result['rc'] == 0:
                assert 'Imported certificate "{}"'.format(adminuser) in result['stdout']
                log.info("Successfully run: {}".format(result['cmd']))
            else:
                log.error("Failed to import certificate.")
                pytest.fail()

    pki_user_add = 'pki -d {} -c {} -p {} -P {} -h {} -n "{}" ca-user-add {} ' \
                   '--fullName {}'.format(constants.NSSDB, constants.CLIENT_DIR_PASSWORD,
                                          constants.CA_HTTPS_PORT, constants.PROTOCOL_SECURE,
                                          'pki1.example.com', adminuser,
                                          adminuser1, adminuser1)

    user_add_out = ansible_module.command(pki_user_add)
    for result in user_add_out.values():
        if result['rc'] == 0:
            assert 'Added user "{}"'.format(adminuser1) in result['stdout']
            assert 'User ID: {}'.format(adminuser1) in result['stdout']
            assert 'Full name: {}'.format(adminuser1) in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()
    userop.remove_user(ansible_module, adminuser)
    userop.remove_user(ansible_module, adminuser1)
    ansible_module.command(client_cert_del + " {}".format(adminuser))


def test_pki_ca_user_cert_add_to_agent_user_use_an_agent_user(ansible_module):
    """
    :Title: Test add agent user, add cert to agent user, approve a cert request as an agent user.
    :Description: Command should show pki ca-user-cert-add, add agent user, add cert to agent  user,
    approve a cert request as an agent user.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add Agent User
        2. Create Certificate, Add it to the Agent user.
        3. Create new certificate request, approve it using agent user.
        4. Add certificate to the agent user.
    :ExpectedResults:
        1. User should get added.
        2. Certificate request should get approved by the agent user.
    :Automated: Yes
    """
    agentuser = 'agentuser'
    fullName = 'Agent User'
    agentuser1 = 'agentuser1'
    fullName1 = 'Agent User1'
    cert_added = False
    userop.add_user(ansible_module, 'add', userid=agentuser, user_name=fullName,
                    type="Certificate Manager Agents")
    add_group = ansible_module.command(basic_pki_cmd +
                                       " group-member-add 'Certificate Manager Agents' "
                                       "{}".format(agentuser))
    for res in add_group.values():
        assert res['rc'] == 0

    subject = "UID={},CN={}".format(agentuser, fullName)

    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')
    if cert_id:
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)

        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTPS_PORT,
                                     protocol='https',
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='{} --serial {}'.format(agentuser, cert_id))

        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Added certificate "{}"'.format(cert_subject) in result['stdout']
                assert 'Cert ID: {}'.format(cert_subject) in result['stdout']
                assert 'Version: 2' in result['stdout']
                assert 'Serial Number: {}'.format(cert_id) in result['stdout']
                assert 'Issuer: {}'.format(CA_SUBJECT) in result['stdout']
                assert 'Subject: {}'.format(subject) in result['stdout']
                log.info("Successfully run: {}".format(result['cmd']))
                cert_added = True
            else:
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()

        if cert_added:
            import_cert = ansible_module.command(basic_pki_cmd + " client-cert-import {} "
                                                                 "--serial {}".format(agentuser,
                                                                                      cert_id))
            for result in import_cert.values():
                if result['rc'] == 0:
                    assert 'Imported certificate "{}"'.format(agentuser) in result['stdout']
                    log.info("Successfully run: {}".format(result['cmd']))
                else:
                    log.error("Failed to import certificate.")
                    pytest.fail()
            subject2 = "UID={},CN={}".format(agentuser1, fullName1)
            new_cert_id = userop.process_certificate_request(ansible_module, subject=subject2,
                                                             request_type='pkcs10', algo='rsa',
                                                             approver_nickname=agentuser,
                                                             keysize='2048', profile='caUserCert')
            if new_cert_id:
                log.info("Generated new certificate {} using {}".format(new_cert_id, agentuser))
            else:
                log.error("Failed to approve new certificate using {}".format(agentuser))
                pytest.fail("")
    userop.remove_user(ansible_module, agentuser)
    ansible_module.command(client_cert_del + " {}".format(agentuser))


@pytest.mark.parametrize("users", ['CA_AuditV', 'CA_AgentV'])
def test_pki_ca_user_cert_add_with_valid_user_certs(ansible_module, users):
    """
    :Title: Test pki ca-user-cert-add, add cert as CA_AgentV should fail
    :Description: Command should show pki ca-user-cert-add, add a cert as CA_AgentV should fail.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. run pki -n "CA_AdminV" ca-user-cert-add --serial <serial> user
        2. run pki -n "CA_AgentV" ca-user-cert-add --serial <serial> user
    :ExpectedResults:
        1. Verify whether pki ca-user-cert-add, add cert as CA_AgentV should fail.
    :Automated: Yes
    """
    user = 'tuser20'
    fullName = 'Test {}'.format(user)
    subject = 'UID={},CN={}'.format(user, fullName)
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')
    if cert_id:
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTPS_PORT,
                                     protocol='https',
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(users),
                                     extra_args='{} --serial {}'.format(user, cert_id))

        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Added certificate "{}"'.format(cert_subject) in result['stdout']
                assert 'Cert ID: {}'.format(cert_subject) in result['stdout']
                assert 'Version: 2' in result['stdout']
                assert 'Serial Number: {}'.format(cert_id) in result['stdout']
                assert 'Issuer: {}'.format(CA_SUBJECT) in result['stdout']
                assert 'Subject: {}'.format(subject) in result['stdout']
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()

            else:
                error = "ForbiddenException: Authorization Error"
                assert error in result['stderr']
                log.info("Successfully run: {}".format(result['cmd']))

    userop.remove_user(ansible_module, user)


@pytest.mark.parametrize("users", ['CA_AdminE', 'CA_AgentE'])
def test_pki_ca_user_cert_add_as_expired_certs(ansible_module, users):
    """
    :Title: Test pki ca-user-cert-add, add cert as CA_AdminE should fail
    :Description: Command should show pki ca-user-cert-add, add a cert as CA_AdminE should fail.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. run pki -n "CA_AdminE" ca-user-cert-add --serial <serial> user
        2. run pki -n "CA_AgentE" ca-user-cert-add --serial <serial> user
    :ExpectedResults:
        1. Adding certs to user as expired certs should fail.
    :Automated: Yes
    """

    user = 'tuser22'
    fullName = 'Test {}'.format(user)

    subject = 'UID={},CN={}'.format(user, fullName)
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')
    if cert_id:
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTPS_PORT,
                                     protocol='https',
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(users),
                                     extra_args='{} --serial {}'.format(user, cert_id))

        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Added certificate "{}"'.format(cert_subject) in result['stdout']
                assert 'Cert ID: {}'.format(cert_subject) in result['stdout']
                assert 'Version: 2' in result['stdout']
                assert 'Serial Number: {}'.format(cert_id) in result['stdout']
                assert 'Issuer: {}'.format(CA_SUBJECT) in result['stdout']
                assert 'Subject: {}'.format(subject) in result['stdout']
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()

            else:
                error = "CERTIFICATE_EXPIRED"
                assert error in result['stderr']
                log.info("Successfully run: {}".format(result['cmd']))

    userop.remove_user(ansible_module, user)


@pytest.mark.parametrize("users", ['CA_AdminR', 'CA_AgentR'])
def test_pki_ca_user_cert_add_as_revoked_certs(ansible_module, users):
    """
    :Title: Test pki ca-user-cert-add, add cert as CA_AdminR should fail
    :Description: Command should show pki ca-user-cert-add, add a cert as CA_AdminR should fail.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. run pki -n "CA_AdminR" ca-user-cert-add --serial <serial> user
        2. run pki -n "CA_AgentR" ca-user-cert-add --serial <serial> user
    :ExpectedResults:
        1. Adding certs using Revoked certs should fail.
    :Automated: Yes
    """

    user = 'tuser23'
    fullName = 'Test {}'.format(user)

    subject = 'UID={},CN={}'.format(user, fullName)
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')
    if cert_id:
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTPS_PORT,
                                     protocol='https',
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(users),
                                     extra_args='{} --serial {}'.format(user, cert_id))

        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Added certificate "{}"'.format(cert_subject) in result['stdout']
                assert 'Cert ID: {}'.format(cert_subject) in result['stdout']
                assert 'Version: 2' in result['stdout']
                assert 'Serial Number: {}'.format(cert_id) in result['stdout']
                assert 'Issuer: {}'.format(CA_SUBJECT) in result['stdout']
                assert 'Subject: {}'.format(subject) in result['stdout']
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()

            else:
                error = "PKIException: Unauthorized"
                assert error in result['stderr']
                log.info("Successfully run: {}".format(result['cmd']))

    userop.remove_user(ansible_module, user)


def test_pki_ca_user_cert_add_as_operatorV(ansible_module):
    """
    :Title: Test pki ca-user-cert-add, add cert as CA_OperatorV should fail
    :Description: Command should show pki ca-user-cert-add, add a cert as CA_OperatorV should fail.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add User CA_OperatorV
        2. Add group Operator. Add CA_Operator to Operator group.
        3. Issue certificate for CA_OperatorV and add it to user.
        4. Import certificate to the client database.
        5. Using the certificate, try to add the certificate to the user.
    :ExpectedResults:
        1. Adding certificate to the user using CA_OperatorV should fail.
    :Automated: Yes
    """

    user = 'CA_OperatorV'
    fullName = 'CA OperatorV'
    subject = 'UID={},CN={}'.format(user, fullName)
    t_user = 'tuser28'
    t_fullName = 'Test user 28'
    t_subject = 'UID={},CN={}'.format(t_user, t_fullName)
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    userop.add_user(ansible_module, 'add', userid=t_user, user_name=t_fullName)

    group_add = basic_pki_cmd + " ca-group-add Operator --description 'Operator Group'"
    group_out = ansible_module.command(group_add)
    for result in group_out.values():
        if result['rc'] == 0:
            group_member_add = basic_pki_cmd + ' ca-group-member-add Operator CA_OperatorV'
            group_member_out = ansible_module.command(group_member_add)
            for res in group_member_out.values():
                try:
                    assert res['rc'] == 0
                except Exception:
                    log.info("Failed to run: {}".format(res['cmd']))
                    pytest.fail()
        else:
            log.info("Failed to run: {}".format(result['cmd']))
            pytest.fail()

    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')
    if cert_id:
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTPS_PORT,
                                     protocol='https',
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='{} --serial {}'.format(user, cert_id))

        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Added certificate "{}"'.format(cert_subject) in result['stdout']
                assert 'Cert ID: {}'.format(cert_subject) in result['stdout']
                assert 'Version: 2' in result['stdout']
                assert 'Serial Number: {}'.format(cert_id) in result['stdout']
                assert 'Issuer: {}'.format(CA_SUBJECT) in result['stdout']
                assert 'Subject: {}'.format(subject) in result['stdout']
                log.info("Successfully run: {}".format(result['cmd']))
                import_cert = ansible_module.command(basic_pki_cmd + " client-cert-import {} "
                                                                     "--serial {}".format(user,
                                                                                          cert_id))
                for r in import_cert.values():
                    if r['rc'] == 0:
                        assert 'Imported certificate "{}"'.format(user) in r['stdout']
                        log.info("Successfully run: {}".format(r['cmd']))
                    else:
                        log.error("Failed to import certificate.")
                        pytest.fail()
            else:
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()

    t_cert_id = userop.process_certificate_request(ansible_module, subject=t_subject,
                                                   request_type='pkcs10', algo='rsa',
                                                   keysize='2048', profile='caUserCert')
    if t_cert_id:
        t_cert_subject = "2;{};{};{}".format(int(t_cert_id, 16), CA_SUBJECT, t_subject)
        t_cmd_out = ansible_module.pki(cli=pki_cmd,
                                       nssdb=constants.NSSDB,
                                       dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                       port=constants.CA_HTTPS_PORT,
                                       protocol='https',
                                       hostname=constants.MASTER_HOSTNAME,
                                       certnick='"{}"'.format(user),
                                       extra_args='{} --serial {}'.format(t_user, t_cert_id))

        for result in t_cmd_out.values():
            if result['rc'] == 0:
                assert 'Added certificate "{}"'.format(t_cert_subject) in result['stdout']
                assert 'Cert ID: {}'.format(t_cert_subject) in result['stdout']
                assert 'Version: 2' in result['stdout']
                assert 'Serial Number: {}'.format(t_cert_id) in result['stdout']
                assert 'Issuer: {}'.format(CA_SUBJECT) in result['stdout']
                assert 'Subject: {}'.format(t_subject) in result['stdout']
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()
            else:
                error = "ForbiddenException: Authorization Error"
                assert error in result['stderr']
                log.info("Successfully run: {}".format(result['cmd']))

    userop.remove_user(ansible_module, user)
    userop.remove_user(ansible_module, t_user)
    group_del = basic_pki_cmd + " ca-group-del Operator"
    ansible_module.command(group_del)
    ansible_module.command(client_cert_del + " {}".format(user))


def test_pki_ca_user_cert_add_to_normal_user(ansible_module):
    """
    :Title: Test pki ca-user-cert-add, add cert as user not associated with any group, should fail
    :Description: Command should show pki ca-user-cert-add, add cert as user not associated with
    any group, should fail.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add User testuser101
        2. Issue certificate for testusre101, add it to the testuser101
        3. Import testuser101 certificate.
        4. Add user using testuser101 certificate.
    :ExpectedResults:
        1. Adding user using testuser101 should fail.
    :Automated: Yes
    """
    user = 'tuser101'
    fullName = 'Test {}'.format(user)
    subject = "UID={},CN={}".format(user, fullName)

    user2 = 'tuser29'
    fullName2 = 'Test {}'.format(user)
    subject2 = 'UID={},CN={}'.format(user2, fullName2)

    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    userop.add_user(ansible_module, 'add', userid=user2, user_name=fullName2)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')
    if cert_id:
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTPS_PORT,
                                     protocol='https',
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='{} --serial {}'.format(user, cert_id))

        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Added certificate "{}"'.format(cert_subject) in result['stdout']
                assert 'Cert ID: {}'.format(cert_subject) in result['stdout']
                assert 'Version: 2' in result['stdout']
                assert 'Serial Number: {}'.format(cert_id) in result['stdout']
                assert 'Issuer: {}'.format(CA_SUBJECT) in result['stdout']
                assert 'Subject: {}'.format(subject) in result['stdout']
                log.info("Successfully run: {}".format(result['cmd']))

                import_cert = ansible_module.command(basic_pki_cmd + " client-cert-import {} "
                                                                     "--serial {}".format(user,
                                                                                          cert_id))
                for r in import_cert.values():
                    if r['rc'] == 0:
                        assert 'Imported certificate "{}"'.format(user) in r['stdout']
                        log.info("Successfully run: {}".format(r['cmd']))
                    else:
                        log.error("Failed to import certificate.")
                        pytest.fail()
            else:
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()

    t_cert_id = userop.process_certificate_request(ansible_module, subject=subject2,
                                                   request_type='pkcs10', algo='rsa',
                                                   keysize='2048', profile='caUserCert')
    if t_cert_id:
        t_cert_subject = "2;{};{};{}".format(int(t_cert_id, 16), CA_SUBJECT, subject2)
        t_cmd_out = ansible_module.pki(cli=pki_cmd,
                                       nssdb=constants.NSSDB,
                                       dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                       port=constants.CA_HTTPS_PORT,
                                       protocol='https',
                                       hostname=constants.MASTER_HOSTNAME,
                                       certnick='"{}"'.format(user),
                                       extra_args='{} --serial {}'.format(user2, t_cert_id))

        for result in t_cmd_out.values():
            if result['rc'] == 0:
                assert 'Added certificate "{}"'.format(t_cert_subject) in result['stdout']
                assert 'Cert ID: {}'.format(t_cert_subject) in result['stdout']
                assert 'Version: 2' in result['stdout']
                assert 'Serial Number: {}'.format(t_cert_id) in result['stdout']
                assert 'Issuer: {}'.format(CA_SUBJECT) in result['stdout']
                assert 'Subject: {}'.format(subject2) in result['stdout']
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()
            else:
                error = "ForbiddenException: Authorization Error"
                assert error in result['stderr']
                log.info("Successfully run: {}".format(result['cmd']))

    userop.remove_user(ansible_module, user)
    userop.remove_user(ansible_module, user2)
    ansible_module.command(client_cert_del + " {}".format(user))


@pytest.mark.parametrize('serial', ['hex', 'dec'])
def test_pki_ca_user_cert_add_with_different_serial(ansible_module, serial):
    """
    :Title: Test pki ca-user-cert-add, add cert to user with --serial option hex and decimal.
    :Description: Add a cert to user with --serial option hex and decimal.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. pki ca-user-cert-add --serial hex user
        1. pki ca-user-cert-add --serial dec user
    :ExpectedResults:
        1. Certificate should get added to the user with --serial option hex.
        2. Certificate should get added to the user with --serial option dec.
    :Automated: Yes
    """

    user = 'tuser31'
    fullName = 'Test User31'
    subject = "UID={},CN={}".format(user, fullName)

    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')

    if cert_id:
        if serial == 'dec':
            certid = int(cert_id, 16)
        else:
            certid = cert_id
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)

        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTPS_PORT,
                                     protocol='https',
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='{} --serial {}'.format(user, certid))

        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Added certificate "{}"'.format(cert_subject) in result['stdout']
                assert 'Cert ID: {}'.format(cert_subject) in result['stdout']
                assert 'Version: 2' in result['stdout']
                assert 'Serial Number: {}'.format(cert_id) in result['stdout']
                assert 'Issuer: {}'.format(CA_SUBJECT) in result['stdout']
                assert 'Subject: {}'.format(subject) in result['stdout']
                log.info("Successfully run: {}".format(result['cmd']))
            else:
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()
    cmd_out = ansible_module.pki(cli='ca-user-cert-find',
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTPS_PORT,
                                 protocol='https',
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(user))
    for result in cmd_out.values():
        if result['rc'] == 0:
            cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
            assert 'Cert ID: {}'.format(cert_subject) in result['stdout']
            assert 'Version: 2' in result['stdout']
            assert 'Serial Number: {}'.format(cert_id) in result['stdout']
            assert 'Issuer: {}'.format(CA_SUBJECT) in result['stdout']
            assert 'Subject: {}'.format(subject) in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_cli_user_cert_add_with_serial_and_input(ansible_module):
    """
    :Title: pki ca-user-cert-add command, add cert to user with --serial and --input should fail.
    :Description: Command should show pki ca-user-cert-add, add a cert to user with --serial and
    --input should fail.   
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. run pki ca-user-cert-add --serial <serial> --input <file>
    :ExpectedResults:
        1. Verify add cert to user with --serial and --input option should fail.
    :Automated: Yes
    """

    user = 'tuser33'
    fullName = 'Test User33'
    subject = 'UID={},CN={}'.format(user, fullName)

    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')
    cert_file = '/tmp/certificate_{}.pem'.format(cert_id)
    export_out = ansible_module.command(basic_pki_cmd + "ca-cert-show {} "
                                                        "--output {}".format(cert_id,
                                                                             cert_file))
    for res in export_out.values():
        assert res['rc'] == 0
    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTPS_PORT,
                                 protocol='https',
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --serial {} --input {}'.format(user, cert_id,
                                                                               cert_file))

    for result in cmd_out.values():
        if result['rc'] == 0:
            cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
            assert 'Cert ID: {}'.format(cert_subject) in result['stdout']
            assert 'Version: 2' in result['stdout']
            assert 'Serial Number: {}'.format(cert_id) in result['stdout']
            assert 'Version: 2' in result['stdout']
            assert 'Serial Number: {}'.format(cert_id) in result['stdout']
            assert 'Issuer: {}'.format(CA_SUBJECT) in result['stdout']
            assert 'Subject: {}'.format(subject) in result['stdout']
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()
        else:
            error = "Conflicting options: --input and --serial."
            assert error in result['stderr']
            log.info("Successfully run: {}".format(result['cmd']))
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_cli_user_cert_add_with_negative_serial(ansible_module):
    """
    :Title: Test pki ca-user-cert-add, add cert to user with negative serial should fail
    :Description: Command should show pki ca-user-cert-add, add cert to user with negative
    serial should fail.   
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add user, Issue certificate for the user.
        2. Add certificate with the negative no.
    :ExpectedResults:
        1. Adding certificate with negative no should not fail.
    :Automated: Yes
    """

    user = 'tuser34'
    fullName = 'Test User34'
    subject = 'UID={},CN={}'.format(user, fullName)

    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')
    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTPS_PORT,
                                 protocol='https',
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --serial {}'.format(user, int(cert_id, 16) * -1))

    for result in cmd_out.values():
        if result['rc'] == 0:
            cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
            assert 'Cert ID: {}'.format(cert_subject) in result['stdout']
            assert 'Version: 2' in result['stdout']
            assert 'Serial Number: {}'.format(cert_id) in result['stdout']
            assert 'Version: 2' in result['stdout']
            assert 'Serial Number: {}'.format(cert_id) in result['stdout']
            assert 'Issuer: {}'.format(CA_SUBJECT) in result['stdout']
            assert 'Subject: {}'.format(subject) in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            error = "NumberFormatException: Zero length BigInteger"
            assert error in result['stderr']
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_cli_user_cert_add_secure_port_with_remote_CA(ansible_module):
    """
    :Title: Bug 1246635 - Add cert to user with secure port and https protocol should succeed.
    :Description: Command should show pki ca-user-cert-add, add cert to user with secure port
    and https protocol should succeed.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add user.
        2. Issue certificate for the user.
        3. Add certificate to the user using secure port and protocol.
    :ExpectedResults:
        1. Add cert to user with secure port and https protocol should succeed.
    :Automated: Yes
    """
    user = 'tuser36'
    fullName = 'Test User36'
    subject = 'UID={},CN={}'.format(user, fullName)

    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')
    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTPS_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 protocol='https',
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --serial {}'.format(user, cert_id))

    for result in cmd_out.values():
        if result['rc'] == 0:
            cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
            assert 'Cert ID: {}'.format(cert_subject) in result['stdout']
            assert 'Version: 2' in result['stdout']
            assert 'Serial Number: {}'.format(cert_id) in result['stdout']
            assert 'Version: 2' in result['stdout']
            assert 'Serial Number: {}'.format(cert_id) in result['stdout']
            assert 'Issuer: {}'.format(CA_SUBJECT) in result['stdout']
            assert 'Subject: {}'.format(subject) in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
    userop.remove_user(ansible_module, user)
