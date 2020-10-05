#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI CA-USER-CERT-SHOW CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki user commands needs to be tested:
#   pki ca-user-cert-show
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

pki_cmd = "ca-user-cert-show"
if TOPOLOGY != '01':
    CA_SUBJECT = 'CN=CA Signing Certificate,OU={},O={}'.format(constants.CA_INSTANCE_NAME,
                                                               constants.CA_SECURITY_DOMAIN_NAME)
else:
    CA_SUBJECT = 'CN=CA Signing Certificate,OU={},O={}'.format('pki-tomcat',
                                                               constants.CA_SECURITY_DOMAIN_NAME)

basic_pki_cmd = 'pki -d {} -c {} -p {} -P {} -n "{}" '.format(constants.NSSDB,
                                                        constants.CLIENT_DIR_PASSWORD,
                                                        constants.CA_HTTP_PORT,
                                                        constants.PROTOCOL_UNSECURE,
                                                        constants.CA_ADMIN_NICK)

group_del = 'pki -d {} -c {} -p {} -P {} -n "{}" ' \
            'ca-group-del '.format(constants.NSSDB, constants.CLIENT_DIR_PASSWORD,
                                   constants.CA_HTTP_PORT, constants.PROTOCOL_UNSECURE,
                                   constants.CA_ADMIN_NICK)

client_cert_del = 'pki -d {} -c {} client-cert-del '.format(constants.NSSDB,
                                                            constants.CLIENT_DIR_PASSWORD)


def add_cert_to_user(ansible_module, user, subject, serial, cert_id):
    cmd_out = ansible_module.pki(cli='ca-user-cert-add',
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --serial {}'.format(user, serial))

    for result in cmd_out.values():
        log.info("Running: {}".format(result['cmd']))
        if result['rc'] == 0:
            assert 'Added certificate "{}"'.format(cert_id) in result['stdout']
            assert 'Cert ID: {}'.format(cert_id) in result['stdout']
            assert 'Version: 2' in result['stdout']
            assert 'Serial Number: {}'.format(serial) in result['stdout']
            assert 'Issuer: {}'.format(CA_SUBJECT) in result['stdout']
            assert 'Subject: {}'.format(subject) in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()


@pytest.mark.parametrize('args', ['', '--help', 'asdfa'])
def test_pki_ca_user_cert_show_help_command(ansible_module, args):
    """
    :Title: Test pki ca-user-cert-show with '', --help and asdfa chars
    :Description: Test pki ca-user-cert-show with '', --help and asdfa chars
    :Requirement: Certificate Authority Users
    :Steps:
        1. pki ca-user-cert-show 
        2. pki ca-user-cert-show --help
        3. pki ca-user-cert-show asdfa
    :ExpectedResults:
        1. It should fail.
        2. It should show help messages
        3. It should fail.
    :Automated: Yes
    :CaseComponent: \-
    """
    help_cmd = 'pki {} {}'.format(pki_cmd, args)
    cmd_out = ansible_module.command(help_cmd)

    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "usage: {} <User ID> <Cert ID> [OPTIONS...]".format(pki_cmd) in result['stdout']
            assert "--encoded         Base-64 encoded" in result['stdout']
            assert "--output <file>   Output file" in result['stdout']
            assert "--pretty          Pretty print" in result['stdout']
            log.info('Successfully ran: {}'.format(result['cmd']))
        elif result['rc'] >= 1:
            assert 'Incorrect number of arguments specified.' in result['stderr']
            log.info('Successfully ran: {}'.format(" ".join(result['cmd'])))
        else:
            log.info('Failed to ran: {}'.format(" ".join(result['cmd'])))
            log.info(result['stderr'])
            pytest.fail()


def test_pki_ca_user_cert_show_valid_userID_and_certID(ansible_module):
    """
    :Title: Test pki ca-user-cert-show cli with valid userID and certID.
    :Description: Show the certs of user with valid userID and certID
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add user.
        2. Add Certificate to user.
        3. pki ca-user-cert-show <valid_userid> <valid_certid>
    :ExpectedResults:
        1. Command should shows the certificates associated with user.
    :Automated: Yes
    :CaseComponent: \-
    """

    user = 'testuser01'
    fullName = 'Test User01'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    subject = 'UID={},CN={}'.format(user, fullName)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')
    if cert_id:
        log.info("Generated certificate with cert ID: {}".format(cert_id))
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
        add_cert_to_user(ansible_module, user, subject, cert_id, cert_subject)

        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='{} "{}"'.format(user, cert_subject))
        for result in cmd_out.values():
            if result['rc'] == 0:
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
        log.error("Failed to generate certificate.")
        pytest.fail("")
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_cert_show_with_invalid_certid(ansible_module):
    """
    :Title: Test pki ca-user-cert-show cli with invalid certID.
    :Description: Show the certs of user with invalid certID, should fail.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add the user
        2. Generate on invalid certificate id.
        3. Run pki ca-user-cert-find <user_id> <invalid_certid>
    :ExpectedResults:
        1. Command should throws the error with invalid certID.
    :Automated: Yes
    :CaseComponent: \-
    """

    user = 'testuser02'
    fullName = 'Test User02'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    subject = 'UID={},CN={}'.format(user, fullName)

    user_cert_id = "2;{};{};{}".format(random.randint(100, 999), CA_SUBJECT, subject)

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} "{}"'.format(user, user_cert_id))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Cert ID:' in result['stdout']
            assert 'Version: 2' in result['stdout']
            assert 'Serial Number: {}' in result['stdout']
            assert 'Issuer:' in result['stdout']
            assert 'Subject:' in result['stdout']
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()

        else:
            error = "ResourceNotFoundException: No certificates found for {}".format(user)
            assert error in result['stderr']
            log.info("Successfully run: {}".format(result['cmd']))
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_cert_show_with_invalid_userid(ansible_module):
    """
    :Title: Test pki ca-user-cert-show cli with invalid userID.
    :Description: Show the certs of user with invalid userID is provided.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Create certificate.
        2. Run pki ca-user-cert-show <invalid_userid> <cert_id>
    :ExpectedResults:
        1. Command should throws the error when invalid userID is provided.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'nonExists'
    subject = 'UID={},CN={}'.format(user, user)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')
    if cert_id:
        log.info("Generated certificate with cert ID: {}".format(cert_id))
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)

        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='{} "{}"'.format(user, cert_subject))
        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Cert ID:' in result['stdout']
                assert 'Version: 2' in result['stdout']
                assert 'Serial Number: {}' in result['stdout']
                assert 'Issuer:' in result['stdout']
                assert 'Subject:' in result['stdout']
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()

            else:
                error = "UserNotFoundException: User {} not found".format(user)
                assert error in result['stderr']
                log.info("Successfully run: {}".format(result['cmd']))

    userop.remove_user(ansible_module, user)


def test_pki_ca_user_cert_show_with_mismatch_of_userid_certid(ansible_module):
    """
    :Title: pki ca-user-cert-show command cli with mismatch of userID and certID.
    :Description: CLI Shows the certs of user with mismatch of userID and certID, should fail.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add user.
        2. Add cert to user.
        3. Run pki ca-user-cert-find caadmin <newly_generate_cert_id>
    :ExpectedResults:
        1. Command should throws the error when mismatch of userID and certID.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'testuser03'
    fullName = 'Test User03'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    subject = 'UID={},CN={}'.format(user, fullName)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')
    if cert_id:
        log.info("Generated certificate with cert ID: {}".format(cert_id))
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
        add_cert_to_user(ansible_module, user, subject, cert_id, cert_subject)

        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='{} "{}"'.format(constants.CA_ADMIN_USERNAME, cert_subject))
        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Cert ID:' in result['stdout']
                assert 'Version: 2' in result['stdout']
                assert 'Serial Number: {}' in result['stdout']
                assert 'Issuer:' in result['stdout']
                assert 'Subject:' in result['stdout']
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()

            else:
                error = "ResourceNotFoundException: No certificates found for caadmin"
                assert error in result['stderr']
                log.info("Successfully run: {}".format(result['cmd']))
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_cert_show_when_userid_is_missing(ansible_module):
    """
    :Title: Test pki ca-user-cert-show CLI with userID is not provided.
    :Description: Command show the certs of a user with userID is not provided, should fail.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add user.
        2. Add certificate to the user.
        3. Run pki ca-user-cert-show <cert_id>
    :ExpectedResults:
        1. Commadn should throws the error when userID is not provided.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'testuser04'
    fullName = 'testuser04'
    subject = 'UID={},CN={}'.format(user, fullName)
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')
    if cert_id:
        log.info("Generated certificate with cert ID: {}".format(cert_id))
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
        add_cert_to_user(ansible_module, user, subject, cert_id, cert_subject)
        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='"{}"'.format(cert_subject))
        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Cert ID:' in result['stdout']
                assert 'Version: 2' in result['stdout']
                assert 'Serial Number: {}' in result['stdout']
                assert 'Issuer:' in result['stdout']
                assert 'Subject:' in result['stdout']
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()

            else:
                error = "Incorrect number of arguments specified."
                assert error in result['stderr']
                log.info("Successfully run: {}".format(result['cmd']))
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_cert_show_when_certid_is_missing1(ansible_module):
    """
    :Title: Test pki ca-user-cert-show CLI with certID is not provided.
    :Description: Command should not show the certs of a user with certID is not provided.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add user.
        2. Run pki ca-user-cert-show <user>
    :ExpectedResults:
        1. Command will throws the error when certID is not provided.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'testuser05'
    fullName = 'Test User05'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='"{}"'.format(user))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Cert ID:' in result['stdout']
            assert 'Version: 2' in result['stdout']
            assert 'Serial Number: {}' in result['stdout']
            assert 'Issuer:' in result['stdout']
            assert 'Subject:' in result['stdout']
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()

        else:
            error = "Incorrect number of arguments specified."
            assert error in result['stderr']
            log.info("Successfully run: {}".format(result['cmd']))
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_cert_show_with_encoded_option(ansible_module):
    """

    :Title: Test pki ca-user-cert-show CLI with valid userID and certID with --encoded option.
    :Description: Command show the certs of a user with valid userID and certID with --encoded option.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add the user.
        2. Add certificate to the user.
        3. Run pki ca-user-cert-show <user_id> <cert_id> --encoded
    :ExpectedResults:
        1. Command shows the certificate id, subject version etc with base64 encoded certificate.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'testuser06'
    fullName = 'Test User06'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    subject = 'UID={},CN={}'.format(user, fullName)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')
    if cert_id:
        log.info("Generated certificate with cert ID: {}".format(cert_id))
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
        add_cert_to_user(ansible_module, user, subject, cert_id, cert_subject)

        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='{} "{}" --encoded'.format(user, cert_subject))
        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Cert ID: {}'.format(cert_subject) in result['stdout']
                assert 'Version: 2' in result['stdout']
                assert 'Serial Number: {}'.format(cert_id) in result['stdout']
                assert 'Issuer: {}'.format(CA_SUBJECT) in result['stdout']
                assert 'Subject: {}'.format(subject) in result['stdout']
                assert '-----BEGIN CERTIFICATE-----' in result['stdout']
                assert '-----END CERTIFICATE-----' in result['stdout']
                log.info("Successfully run: {}".format(result['cmd']))
            else:
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()
    else:
        log.error("Failed to generate certificate.")
        pytest.fail("")
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_cert_show_when_userid_not_provided_with_encoded(ansible_module):
    """
    :Title: Test pki ca-user-cert-show CLI when userID not provided with valid certID and --encoded option.
    :Description: Command should the certs of a user when userID not provided with valid certID and --encoded option.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add the user
        2. Add certificate to he user.
    :ExpectedResults:
        1. Command should throws the error.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'testuser07'
    fullName = 'Test User07'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    subject = 'UID={},CN={}'.format(user, fullName)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')
    if cert_id:
        log.info("Generated certificate with cert ID: {}".format(cert_id))
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
        add_cert_to_user(ansible_module, user, subject, cert_id, cert_subject)
        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='"{}" --encoded'.format(cert_subject))
        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Cert ID:' in result['stdout']
                assert 'Version: 2' in result['stdout']
                assert 'Serial Number: {}' in result['stdout']
                assert 'Issuer:' in result['stdout']
                assert 'Subject:' in result['stdout']
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()

            else:
                error = "Incorrect number of arguments specified."
                assert error in result['stderr']
                log.info("Successfully run: {}".format(result['cmd']))
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_cert_show_when_certid_not_provided_with_encoded(ansible_module):
    """
    :Title: Test pki ca-user-cert-show CLI when certID not provided with valid userID and --encoded option.
    :Description: Command show the certs of a user when certid not provided with valid userID and  --encoded option.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add the user
        2. Add the certificate to user.
        3. Run pki ca-user-cert-show <userid> --encoded
    :ExpectedResults:
        1. Verify whether pki ca-user-cert-show will throws the error.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'testuser08'
    fullName = 'Test User08'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    subject = 'UID={},CN={}'.format(user, fullName)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')
    if cert_id:
        log.info("Generated certificate with cert ID: {}".format(cert_id))
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
        add_cert_to_user(ansible_module, user, subject, cert_id, cert_subject)
        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='"{}" --encoded'.format(user))
        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Cert ID:' in result['stdout']
                assert 'Version: 2' in result['stdout']
                assert 'Serial Number: {}' in result['stdout']
                assert 'Issuer:' in result['stdout']
                assert 'Subject:' in result['stdout']
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()

            else:
                error = "Incorrect number of arguments specified."
                assert error in result['stderr']
                log.info("Successfully run: {}".format(result['cmd']))
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_cert_show_with_output_options(ansible_module):
    """
    :Title: Test pki ca-user-cert-show CLI with valid userID and certID --output option.
    :Description: Show the certs of user with valid userID and certID --output option.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add user
        2. Add certificate to the user
        3. Run pki ca-user-cert-find <userid> <cert_id> --output /tmp/certificate.pem
    :ExpectedResults:
        1. Command should create output file with --output option.
        3. Certificate should be present in the file.
    :Automated: Yes
    :CaseComponent: \-
    """

    user = 'testuser09'
    fullName = 'Test User09'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    output_file = None
    subject = 'UID={},CN={}'.format(user, fullName)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')
    if cert_id:
        output_file = '/tmp/cert_{}.pem'.format(cert_id)
        log.info("Generated certificate with cert ID: {}".format(cert_id))
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
        add_cert_to_user(ansible_module, user, subject, cert_id, cert_subject)
        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='{} "{}" --output {}'.format(user, cert_subject, output_file))
        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Cert ID: {}'.format(cert_subject) in result['stdout']
                assert 'Version: 2' in result['stdout']
                assert 'Serial Number: {}'.format(cert_id) in result['stdout']
                assert 'Issuer: {}'.format(CA_SUBJECT) in result['stdout']
                assert 'Subject: {}'.format(subject) in result['stdout']

                file_stat = ansible_module.stat(path=output_file)
                for result1 in file_stat.values():
                    assert result1['stat']['exists'] == True
                    log.info("File existed.")

                file_content = ansible_module.shell('cat {}'.format(output_file))
                for result2 in file_content.values():
                    assert '-----BEGIN CERTIFICATE-----' in result2['stdout']
                    assert '-----END CERTIFICATE-----' in result2['stdout']
                    log.info("Base64 certificate present in the file.")

                log.info("Successfully run: {}".format(result['cmd']))

            else:
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()
    userop.remove_user(ansible_module, user)
    ansible_module.shell("rm -rf {}".format(output_file))


def test_pki_ca_user_cert_show_when_userid_is_missing_with_output_option(ansible_module):
    """
    :Title: Test pki ca-user-cert-show CLI when userID is not provided with valid certID and --output option.
    :Description: Command should show the certs of user when userID is not provided with valid certID and --output option.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add user.
        2. Add cert to the user.
        3. Run pki ca-user-cert-show <cert_id> --output /tmp/cert.pem
    :ExpectedResults:
        1. Command should throws the error.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'testuser10'
    fullName = 'Test User10'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    subject = 'UID={},CN={}'.format(user, fullName)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')
    if cert_id:
        output_file = '/tmp/cert_{}.pem'.format(cert_id)
        log.info("Generated certificate with cert ID: {}".format(cert_id))
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
        add_cert_to_user(ansible_module, user, subject, cert_id, cert_subject)
        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='"{}" --output {}'.format(cert_subject, output_file))
        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Cert ID:' in result['stdout']
                assert 'Version: 2' in result['stdout']
                assert 'Serial Number: {}' in result['stdout']
                assert 'Issuer:' in result['stdout']
                assert 'Subject:' in result['stdout']
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()

            else:
                error = "Incorrect number of arguments specified."
                assert error in result['stderr']
                file_stat = ansible_module.stat(path=output_file)
                for result1 in file_stat.values():
                    assert result1['stat']['exists'] == False
                    log.info("File not existed.")
                log.info("Successfully run: {}".format(result['cmd']))
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_cert_show_when_certid_is_missing_with_output_option(ansible_module):
    """
    :Title: Test pki ca-user-cert-show when certID is not provided with valid userID and --output option.
    :Description: Command should show the certs of user when certID is not provided with valid userID and --output option.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add user
        2. Add certificate to user.
        2. Run pki ca-user-cert-find <userid> --output /tmp/cert.pem
    :ExpectedResults:
        1. Command should throws the error.
    :Automated: Yes
    :CaseComponent: \-
    """

    user = 'testuser10'
    fullName = 'Test User10'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    subject = 'UID={},CN={}'.format(user, fullName)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')
    if cert_id:
        output_file = '/tmp/cert_{}.pem'.format(cert_id)
        log.info("Generated certificate with cert ID: {}".format(cert_id))
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
        add_cert_to_user(ansible_module, user, subject, cert_id, cert_subject)
        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='{} --output {}'.format(user, output_file))
        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Cert ID:' in result['stdout']
                assert 'Version: 2' in result['stdout']
                assert 'Serial Number: {}' in result['stdout']
                assert 'Issuer:' in result['stdout']
                assert 'Subject:' in result['stdout']
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()

            else:
                error = "Incorrect number of arguments specified."
                assert error in result['stderr']
                file_stat = ansible_module.stat(path=output_file)
                for result1 in file_stat.values():
                    assert result1['stat']['exists'] == False
                    log.info("File not existed.")
                log.info("Successfully run: {}".format(result['cmd']))
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_cert_show_with_output_directory_does_not_exists(ansible_module):
    """
    :Title: Test pki ca-user-cert-show CLI with valid userID,certID, --output <file> directory does not exits.
    :Description: Command should show the certs of user with valid userID and certID, should fail if
    --output <file> directory does not exits.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add the user.
        2. Add the certificate to user.
        3. Run pki ca-user-cert-show <userid> <cert-id> --output <invalid_path>
    :ExpectedResults:
        1. Command should throws the error.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'testuser11'
    fullName = 'Test User11'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    subject = 'UID={},CN={}'.format(user, fullName)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')
    if cert_id:
        output_file = '/tmp/asdfa/cert_{}.pem'.format(cert_id)
        log.info("Generated certificate with cert ID: {}".format(cert_id))
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
        add_cert_to_user(ansible_module, user, subject, cert_id, cert_subject)
        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='{} "{}" --output {}'.format(user, cert_subject, output_file))
        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Cert ID:' in result['stdout']
                assert 'Version: 2' in result['stdout']
                assert 'Serial Number: {}' in result['stdout']
                assert 'Issuer:' in result['stdout']
                assert 'Subject:' in result['stdout']
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()
            else:
                error = "FileNotFoundException: {} (No such file or directory)".format(output_file)
                assert error in result['stderr']
                file_stat = ansible_module.stat(path=output_file)
                for result1 in file_stat.values():
                    assert result1['stat']['exists'] == False
                    log.info("File not existed.")
                log.info("Successfully run: {}".format(result['cmd']))
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_cert_show_output_option_file_argument_not_provided(ansible_module):
    """
    :Title: Test pki ca-user-cert-show CLI when --output option file argument is not provided.
    :Description: Command should show pki ca-user-cert-show when  --output option file argument is not provided.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add user.
        2. Add cert to user.
        3. Run pki ca-user-cert-find <user_id> <cert_id> --output
    :ExpectedResults:
        1. Command should throws the error.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'testuser12'
    fullName = 'Test User12'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    subject = 'UID={},CN={}'.format(user, fullName)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')
    if cert_id:
        log.info("Generated certificate with cert ID: {}".format(cert_id))
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
        add_cert_to_user(ansible_module, user, subject, cert_id, cert_subject)
        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='{} "{}" --output'.format(user, cert_subject))
        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Cert ID:' in result['stdout']
                assert 'Version: 2' in result['stdout']
                assert 'Serial Number: {}' in result['stdout']
                assert 'Issuer:' in result['stdout']
                assert 'Subject:' in result['stdout']
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()
            else:
                error = "MissingArgumentException: Missing argument for option: output"
                assert error in result['stderr']
                log.info("Successfully run: {}".format(result['cmd']))
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_cert_show_with_pretty_option(ansible_module):
    """
    :Title: Test pki ca-user-cert-show CLI --pretty option shows the certificate in pretty print format.
    :Description: --pretty option with CLI shows the certificate in pretty print format.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add the user.
        2. Add certificate to user.
        3. Run pki ca-user-cert-show <user_id> <cert_id> --pretty
    :ExpectedResults:
        1. Command should shows the certificate in pretty print format.
    :Automated: Yes
    :CaseComponent: \-
    """

    user = 'testuser13'
    fullName = 'Test User13'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    subject = 'UID={},CN={}'.format(user, fullName)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')
    if cert_id:
        log.info("Generated certificate with cert ID: {}".format(cert_id))
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
        add_cert_to_user(ansible_module, user, subject, cert_id, cert_subject)
        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='{} "{}" --pretty'.format(user, cert_subject))
        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Certificate "{}"'.format(cert_subject) in result['stdout']
                assert 'Serial Number: {}'.format(cert_id) in result['stdout']
                assert 'Issuer: {}'.format(CA_SUBJECT) in result['stdout']
                assert 'Subject: {}'.format(subject) in result['stdout']
                assert 'Not Before: ' in result['stdout']
                assert 'Not  After: ' in result['stdout']
                assert 'Certificate:' in result['stdout']
                assert 'Data:' in result['stdout']
                assert 'Version:  v3' in result['stdout']
                assert 'Serial Number: {}'.format(cert_id) in result['stdout']
                assert 'Signature Algorithm:' in result['stdout']
                assert 'Subject Public Key Info:' in result['stdout']
                assert 'Algorithm:' in result['stdout']
                assert 'Public Key:' in result['stdout']
                assert 'Exponent:' in result['stdout']
                assert 'Public Key Modulus:' in result['stdout']
                assert 'Extensions:' in result['stdout']
                assert 'Signature:' in result['stdout']
                assert 'FingerPrint' in result['stdout']
                assert 'MD2:' in result['stdout']
                assert 'MD5:' in result['stdout']
                assert 'SHA-1:' in result['stdout']
                assert 'SHA-256:' in result['stdout']
                assert 'SHA-512:' in result['stdout']
                log.info("Successfully run: {}".format(result['cmd']))

            else:
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_cert_show_when_userid_is_missing_with_pretty_op(ansible_module):
    """
    :Title: Test pki ca-user-cert-show CLI when userID not provided with --pretty option.
    :Description: Command should show pki ca-user-cert-show CLI when userID not provided with --pretty option.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add the user.
        2. Add certificate to user.
        3. Run pki ca-user-cert-show <cert_id> --pretty
    :ExpectedResults:
        1. Command should throws the error.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'testuser14'
    fullName = 'Test User14'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    subject = 'UID={},CN={}'.format(user, fullName)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')
    if cert_id:
        log.info("Generated certificate with cert ID: {}".format(cert_id))
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
        add_cert_to_user(ansible_module, user, subject, cert_id, cert_subject)
        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='"{}" --pretty'.format(cert_subject))
        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Cert ID:' in result['stdout']
                assert 'Version: 2' in result['stdout']
                assert 'Serial Number: {}' in result['stdout']
                assert 'Issuer:' in result['stdout']
                assert 'Subject:' in result['stdout']
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()

            else:
                error = "Incorrect number of arguments specified."
                assert error in result['stderr']
                log.info("Successfully run: {}".format(result['cmd']))
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_cert_show_when_certid_missing_with_pretty(ansible_module):
    """
    :Title: Test pki ca-user-cert-show CLI when certID not provided with --pretty option.
    :Description: Command should show pki ca-user-cert-show CLI when certID not provided with --pretty option.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add the user.
        2. Add certificate to user.
        3. Run pki ca-user-cert-show <cuser_id> --pretty
    :ExpectedResults:
        1. Command should throws the error.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'testuser15'
    fullName = 'Test User15'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    subject = 'UID={},CN={}'.format(user, fullName)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')
    if cert_id:
        log.info("Generated certificate with cert ID: {}".format(cert_id))
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
        add_cert_to_user(ansible_module, user, subject, cert_id, cert_subject)
        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='{} --pretty'.format(user))
        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Cert ID:' in result['stdout']
                assert 'Version: 2' in result['stdout']
                assert 'Serial Number: {}' in result['stdout']
                assert 'Issuer:' in result['stdout']
                assert 'Subject:' in result['stdout']
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()

            else:
                error = "Incorrect number of arguments specified."
                assert error in result['stderr']
                log.info("Successfully run: {}".format(result['cmd']))
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_cert_show_with_output_pretty_and_encoded_option(ansible_module):
    """
    :Title: Test pki ca-user-cert-show CLI with --pretty, --output and --encoded option.
    :Description: Command should fail, with --pretty, --output, and --encoded option.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add the user.
        2. Add certificate to user.
        3. Run pki ca-user-cert-show <user_id> <cert_id> --pretty --encoded --output /tmp/cert.pem
    :ExpectedResults:
        1. Command should throws the error when all three options are provided.
    :ExpectedResults: Verify whether pki ca-user-cert-show will
    :Automated: Yes
    :CaseComponent: \-
    """

    user = 'testuser16'
    fullName = 'Test User16'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    subject = 'UID={},CN={}'.format(user, fullName)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')
    if cert_id:
        output_file = '/tmp/cert_{}.pem'.format(cert_id)
        log.info("Generated certificate with cert ID: {}".format(cert_id))
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
        add_cert_to_user(ansible_module, user, subject, cert_id, cert_subject)
        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='{} "{}" --pretty --encoded '
                                                '--output {}'.format(user, cert_subject, output_file))
        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Certificate "{}"'.format(cert_subject) in result['stdout']
                assert 'Serial Number: {}'.format(cert_id) in result['stdout']
                assert 'Issuer: {}'.format(CA_SUBJECT) in result['stdout']
                assert 'Subject: {}'.format(subject) in result['stdout']
                assert 'Not Before: ' in result['stdout']
                assert 'Not  After: ' in result['stdout']
                assert 'Certificate:' in result['stdout']
                assert 'Data:' in result['stdout']
                assert 'Version:  v3' in result['stdout']
                assert 'Serial Number: {}'.format(cert_id) in result['stdout']
                assert 'Signature Algorithm:' in result['stdout']
                assert 'Subject Public Key Info:' in result['stdout']
                assert 'Algorithm:' in result['stdout']
                assert 'Public Key:' in result['stdout']
                assert 'Exponent:' in result['stdout']
                assert 'Public Key Modulus:' in result['stdout']
                assert 'Extensions:' in result['stdout']
                assert 'Signature:' in result['stdout']
                assert 'FingerPrint' in result['stdout']
                assert 'MD2:' in result['stdout']
                assert 'MD5:' in result['stdout']
                assert 'SHA-1:' in result['stdout']
                assert 'SHA-256:' in result['stdout']
                assert 'SHA-512:' in result['stdout']
                file_stat = ansible_module.stat(path=output_file)
                for result1 in file_stat.values():
                    assert result1['stat']['exists'] == True
                    log.info("File existed.")

                file_content = ansible_module.shell('cat {}'.format(output_file))
                for result2 in file_content.values():
                    assert '-----BEGIN CERTIFICATE-----' in result2['stdout']
                    assert '-----END CERTIFICATE-----' in result2['stdout']
                    log.info("Base64 certificate present in the file.")
                log.info("Successfully run: {}".format(result['cmd']))
            else:
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()
    userop.remove_user(ansible_module, user)


@pytest.mark.parametrize("user_type", ['CA_AuditV', 'CA_AgentV'])
def test_pki_ca_user_cert_show_with_valid_user_certs(ansible_module, user_type):
    """
    :Title: Test pki ca-user-cert-show CLI show certs as CA_AuditV and CA_AgentV
    :Description: Show the certs of user as a CA_AgentV and CA_AgentV, should fail.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add user
        2. Add certificate to user.
        3. Run pki -n CA_AgentV ca-user-cert-show <user_id> <cert_id>
        4. Run pki -n CA_AuditV ca-user-cert-show <user_id> <cert_id>
    :ExpectedResults:
        1. Command should throws the error when accessing as CA_AgentV.
        2. Command should throws the error when accessing as CA_AuditV.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'testuser17'
    fullName = 'Test User17'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    subject = 'UID={},CN={}'.format(user, fullName)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')
    if cert_id:
        log.info("Generated certificate with cert ID: {}".format(cert_id))
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
        add_cert_to_user(ansible_module, user, subject, cert_id, cert_subject)
        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(user_type),
                                     extra_args='{} "{}"'.format(user, cert_subject))
        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Cert ID:' in result['stdout']
                assert 'Version: 2' in result['stdout']
                assert 'Serial Number: {}' in result['stdout']
                assert 'Issuer:' in result['stdout']
                assert 'Subject:' in result['stdout']
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()

            else:
                error = "ForbiddenException: Authorization Error"
                assert error in result['stderr']
                log.info("Successfully run: {}".format(result['cmd']))
    userop.remove_user(ansible_module, user)


@pytest.mark.parametrize("user_type", ['CA_AuditE', 'CA_AgentE', 'CA_AdminE'])
def test_pki_ca_user_cert_show_with_expired_user_certs(ansible_module, user_type):
    """
    :Title: Test pki ca-user-cert-show CLI show user certs as CA_AdminE, CA_AgentE, CA_AuditE.
    :Description: Command should show the certs of user as CA_AdminE, CA_AgentE, CA_AuditE, should fail.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add user
        2. Add certificate to user.
        3. Run pki -n CA_AgentE ca-user-cert-show <user_id> <cert_id>
        4. Run pki -n CA_AuditE ca-user-cert-show <user_id> <cert_id>
        5. Run pki -n CA_AdminE ca-user-cert-show <user_id> <cert_id>
    :ExpectedResults:
        1. Command should throws the error when accessing as CA_AgentE.
        2. Command should throws the error when accessing as CA_AuditE.
        3. Command should throws the error when accessing as CA_AdminE.
    :Automated: Yes

    :CaseComponent: \-
    """
    user = 'testuser18'
    fullName = 'Test User18'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    subject = 'UID={},CN={}'.format(user, fullName)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')
    if cert_id:
        log.info("Generated certificate with cert ID: {}".format(cert_id))
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
        add_cert_to_user(ansible_module, user, subject, cert_id, cert_subject)
        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(user_type),
                                     extra_args='{} "{}"'.format(user, cert_subject))
        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Cert ID:' in result['stdout']
                assert 'Version: 2' in result['stdout']
                assert 'Serial Number: {}' in result['stdout']
                assert 'Issuer:' in result['stdout']
                assert 'Subject:' in result['stdout']
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()

            else:
                assert "SEVERE: FATAL: SSL alert received: CERTIFICATE_EXPIRED\nIOException: " \
                       "SocketException cannot read on socket: Error reading from socket: " \
                       "(-12269) SSL peer rejected your certificate as expired." in result['stderr']
                log.info("Successfully run: {}".format(result['cmd']))
    userop.remove_user(ansible_module, user)


@pytest.mark.parametrize("user_type", ['CA_AuditR', 'CA_AgentR', 'CA_AdminR'])
def test_pki_ca_user_cert_show_with_revoked_cert_users(ansible_module, user_type):
    """
    :Title: Test pki ca-user-cert-show, CLI with admin as CA_AdminR, CA_AgnetR,CA_AuditR
    :Description: Command should show pki ca-user-cert-show CLI with admin as CA_AdminR, CA_AgentR, CA_AuditR should fail.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add user
        2. Add certificate to user.
        3. Run pki -n CA_AgentR ca-user-cert-show <user_id> <cert_id>
        4. Run pki -n CA_AuditR ca-user-cert-show <user_id> <cert_id>
        5. Run pki -n CA_AdminR ca-user-cert-show <user_id> <cert_id>
    :ExpectedResults:
        1. Command should throws the error when accessing as CA_AgentR.
        2. Command should throws the error when accessing as CA_AuditR.
        3. Command should throws the error when accessing as CA_AdminR
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'testuser20'
    fullName = 'Test User20'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    subject = 'UID={},CN={}'.format(user, fullName)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')
    if cert_id:
        log.info("Generated certificate with cert ID: {}".format(cert_id))
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
        add_cert_to_user(ansible_module, user, subject, cert_id, cert_subject)
        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(user_type),
                                     extra_args='{} "{}"'.format(user, cert_subject))
        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Cert ID:' in result['stdout']
                assert 'Version: 2' in result['stdout']
                assert 'Serial Number: {}' in result['stdout']
                assert 'Issuer:' in result['stdout']
                assert 'Subject:' in result['stdout']
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()

            else:
                error = "PKIException: Unauthorized"
                assert error in result['stderr']
                log.info("Successfully run: {}".format(result['cmd']))
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_cert_show_with_incomplete_certid(ansible_module):
    """
    :Title: Test pki ca-user-cert-show CLI when incomplete certID is provided
    :Description: Command should show pki ca-user-cert-show CLI when incomplete certID is provided, should fail.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add user
        2. Add certificate to user.
        3. Run pki ca-user-cert-show <user_id> <incomplete_cert_id>
    :ExpectedResults:
        1. Command should throws the error when incomplete certID is provided.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'testuser19'
    fullName = 'Test User19'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    subject = 'UID={},CN={}'.format(user, fullName)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')
    if cert_id:
        log.info("Generated certificate with cert ID: {}".format(cert_id))
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
        add_cert_to_user(ansible_module, user, subject, cert_id, cert_subject)
        cert_subject1 = "2;{};{}".format(int(cert_id, 16), CA_SUBJECT)

        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='{} "{}"'.format(user, cert_subject1))
        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Cert ID:' in result['stdout']
                assert 'Version: 2' in result['stdout']
                assert 'Serial Number: {}' in result['stdout']
                assert 'Issuer:' in result['stdout']
                assert 'Subject:' in result['stdout']
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()

            else:
                error = "ResourceNotFoundException: No certificates found for {}".format(user)
                assert error in result['stderr']
                log.info("Successfully run: {}".format(result['cmd']))
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_cert_show_as_a_ca_operatorv(ansible_module):
    """
    :Title: Test pki ca-user-cert-show CLI admin as a CA_OperatorV should fail
    :Description: Command should show pki ca-user-cert-show CLI admin as a CA_OperatorV should fail.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add user
        2. Add certificate to user.
        3. Run pki -n CA_OperatorV ca-user-cert-show <user_id> <incomplete_cert_id>
    :ExpectedResults:
        1. Command should throws the error when accessing as CA_OperatorV.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = "CA_OperatorV"
    fullName = 'CA OperatorV'
    t_user = 'TestE3{}'.format(random.randint(111, 9999))
    t_full_name = 'User {}'.format(user)
    group = 'Operator'
    subject = 'UID={},CN={},OU=Engineering,O=Example'.format(user, fullName)
    group_add = basic_pki_cmd + ' ca-group-add {} --description "Operator Group"'.format(group)

    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    userop.add_user(ansible_module, 'add', userid=t_user, user_name=t_full_name)
    ansible_module.command(group_add)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 profile='caUserCert',
                                                 keysize=2048)
    log.info("Generated certificate for the user, Cert ID: {}".format(cert_id))
    if cert_id:
        log.info("Generated certificate with cert ID: {}".format(cert_id))
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
        add_cert_to_user(ansible_module, user, subject, cert_id, cert_subject)
        import_cert = basic_pki_cmd + ' client-cert-import {} --serial {}'.format(user, cert_id)
        import_out = ansible_module.command(import_cert)
        for res in import_out.values():
            if res['rc'] == 0:
                assert 'Imported certificate "{}"'.format(user) in res['stdout']
            else:
                log.error("Failed to import the certificate.")
                pytest.fail("Failed to import certificate.")

    cert_cert_find_out = ansible_module.pki(cli=pki_cmd,
                                            nssdb=constants.NSSDB,
                                            dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                            port=constants.CA_HTTP_PORT,
                                            hostname=constants.MASTER_HOSTNAME,
                                            certnick='"{}"'.format(user),
                                            extra_args='{} "{}"'.format(user, cert_subject))
    for result in cert_cert_find_out.values():
        if result['rc'] == 0:
            assert 'Cert ID:' in result['stdout']
            assert 'Version: 2' in result['stdout']
            assert 'Serial Number: {}' in result['stdout']
            assert 'Issuer:' in result['stdout']
            assert 'Subject:' in result['stdout']
            log.error('Failed to run: {}'.format(result['cmd']))
            pytest.fail('Failed to ran: {}'.format(result['cmd']))
        else:
            error = "ForbiddenException: Authorization Error"
            assert error in result['stderr']
            log.info('Successfully ran {}.'.format(result['cmd']))
    userop.remove_user(ansible_module, user)
    userop.remove_user(ansible_module, t_user)
    ansible_module.command(group_del + group)
    ansible_module.command(client_cert_del + '"{}"'.format(user))


def test_pki_ca_user_cert_show_with_encoded_and_output_options(ansible_module):
    """
    :Title: Test pki ca-user-cert-show CLI with encoded and --output options
    :Description: Command should show pki ca-user-cert-show CLI with encoded and --output options.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add user.
        2. Add certificate to user.
        3. Run pki ca-user-cert-show <user_id> <cert_id> --encoded --ouput /tmp/cert.pem
    :ExpectedResults:
        1. Command should store in file.
        2. Command should show the certificate.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'testuser21'
    fullName = 'Test User21'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    subject = 'UID={},CN={}'.format(user, fullName)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')
    if cert_id:
        output_file = '/tmp/cert_{}.pem'.format(cert_id)
        log.info("Generated certificate with cert ID: {}".format(cert_id))
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
        add_cert_to_user(ansible_module, user, subject, cert_id, cert_subject)
        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='{} "{}" --encoded --output {}'.format(user, cert_subject, output_file))
        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Cert ID:' in result['stdout']
                assert 'Version: 2' in result['stdout']
                assert 'Serial Number: {}'.format(cert_id) in result['stdout']
                assert 'Issuer:' in result['stdout']
                assert 'Subject:' in result['stdout']
                assert '-----BEGIN CERTIFICATE-----' in result['stdout']
                assert '-----END CERTIFICATE-----' in result['stdout']
                file_stat = ansible_module.stat(path=output_file)
                for result1 in file_stat.values():
                    assert result1['stat']['exists'] == True
                    log.info("File existed.")

                file_content = ansible_module.shell('cat {}'.format(output_file))
                for result2 in file_content.values():
                    assert '-----BEGIN CERTIFICATE-----' in result2['stdout']
                    assert '-----END CERTIFICATE-----' in result2['stdout']
                    log.info("Base64 certificate present in the file.")
                log.info("Successfully run: {}".format(result['cmd']))
            else:
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()


def test_pki_ca_user_cert_show_when_user_not_associated_with_any_group(ansible_module):
    """
    :Title: Test pki ca-user-cert-show CLI access using use who is not associate with any group.
    :Description: Command should show pki ca-user-cert-show CLI access using use who is not associate with any group.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add user
        2. Add certificate to user.
        3. Run pki -n testuser22 ca-user-cert-show <user_id> <cert_id>
    :ExpectedResults:
        1. Command should throw the error when user not associated with any role.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'testuser22'
    fullName = 'Test User22'
    t_user1 = 'testuser111'
    t_user_fullName = 'Test User111'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    userop.add_user(ansible_module, 'add', userid=t_user1, user_name=t_user_fullName)

    subject = 'UID={},CN={}'.format(user, fullName)
    subject1 = 'UID={},CN={}'.format(t_user1, t_user_fullName)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')
    cert_id1 = userop.process_certificate_request(ansible_module, subject=subject1,
                                                  request_type='pkcs10', algo='rsa',
                                                  keysize='2048', profile='caUserCert')
    if cert_id:
        log.info("Generated certificate with cert ID: {}".format(cert_id1))
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
        cert_subject1 = "2;{};{};{}".format(int(cert_id1, 16), CA_SUBJECT, subject1)
        add_cert_to_user(ansible_module, user, subject, cert_id, cert_subject)
        add_cert_to_user(ansible_module, t_user1, subject1, cert_id1, cert_subject1)
        import_cert = basic_pki_cmd + ' client-cert-import {} --serial {}'.format(user, cert_id)
        import_out = ansible_module.command(import_cert)
        for res in import_out.values():
            if res['rc'] == 0:
                assert 'Imported certificate "{}"'.format(user) in res['stdout']
            else:
                log.error("Failed to import the certificate.")
                pytest.fail("Failed to import certificate.")
        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(user),
                                     extra_args='{} "{}"'.format(t_user1, cert_subject1))
        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Cert ID:' in result['stdout']
                assert 'Version: 2' in result['stdout']
                assert 'Serial Number: {}'.format(cert_id) in result['stdout']
                assert 'Issuer:' in result['stdout']
                assert 'Subject:' in result['stdout']
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()
            else:
                assert "ForbiddenException: Authorization Error" in result['stderr']
                log.info("Successfully run: {}".format(result['cmd']))
    userop.remove_user(ansible_module, user)
    userop.remove_user(ansible_module, t_user1)
    ansible_module.command('pki -d {} -c {} client-cert-del '
                           '{}'.format(constants.NSSDB, constants.CLIENT_DIR_PASSWORD, user))
