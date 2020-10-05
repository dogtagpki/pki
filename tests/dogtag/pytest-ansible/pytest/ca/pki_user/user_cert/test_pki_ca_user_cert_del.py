#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI CA-USER-CERT-DEL CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki user commands needs to be tested:
#   pki ca-user-cert-del
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

pki_cmd = "ca-user-cert-del"
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
                                   constants.CA_HTTPS_PORT, constants.PROTOCOL_SECURE,
                                   constants.CA_ADMIN_NICK)

client_cert_del = 'pki -d {} -c {} client-cert-del '.format(constants.NSSDB,
                                                            constants.CLIENT_DIR_PASSWORD)


def add_cert_to_user(ansible_module, user, subject, serial, cert_id):
    cmd_out = ansible_module.pki(cli='ca-user-cert-add',
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTPS_PORT,
                                 protocol='https',
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


@pytest.mark.parametrize('args', ['--help', '', 'asdfa'])
def test_pki_ca_user_cert_del_help_command(ansible_module, args):
    """
    :Title: Test pki ca-user-cert-del --help command
    :Description: Command should show pki ca-user-cert-del --help command options.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults:
        1. Verify whether pki ca-user-cert-del --help command should show the options.
    :Automated: Yes
    """

    cer_del_help = 'pki {} {}'.format(pki_cmd, args)
    del_help_out = ansible_module.command(cer_del_help)
    for result in del_help_out.values():
        if result['rc'] == 0:
            assert "usage: {} <User ID> <Cert ID> [OPTIONS...]".format(pki_cmd) in result['stdout']
            assert re.search("--help\s+Show help message.", result['stdout'])
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            assert 'Incorrect number of arguments specified.' in result['stderr']


def test_pki_ca_user_cert_del_valid_user_id_valid_cert_id(ansible_module):
    """
    :Title: Test pki ca-user-cert-del, Delete cert assigned to user with valid userID and Valid certID
    :Description: Command should delete certificate assigned to user using ca-user-cert-del.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. pki ca-user-cert-del <userid> <cert_id>
    :ExpectedResults:
        1. Verify whether pki ca-user-cert-del should delete the certificate which is assigned to user.
    :Automated: Yes
    """
    user = 'tuser1'
    fullName = 'Test User1'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    cert_ids = []

    for i in range(2):
        uid = "tuser1.{}".format(i)
        subject = "UID={},E={}@example.com,CN={}".format(uid, uid, fullName)

        cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                     request_type='pkcs10', algo='rsa',
                                                     keysize='2048', profile='caUserCert')
        if cert_id:
            log.info("Generated certificate request with cert ID: {}".format(cert_id))
            cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
            cert_ids.append(cert_subject)
            add_cert_to_user(ansible_module, user, subject, cert_id, cert_subject)
        else:
            log.error("Failed to generate certificate.")
            pytest.fail("")
    for cert_sub in cert_ids:
        cert_id = hex(int(cert_sub.split(";")[1]))
        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTPS_PORT,
                                     protocol='https',
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='{} "{}"'.format(user, cert_sub))

        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Deleted certificate "{}"'.format(cert_sub) in result['stdout']
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
                assert 'Cert ID: {}'.format(cert_sub) not in result['stdout']
                assert 'Serial Number: {}'.format(cert_id) not in result['stdout']
                log.info("Successfully run: {}".format(result['cmd']))
            else:
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()

    userop.remove_user(ansible_module, user)


def test_pki_ca_user_cert_del_with_invalid_cert_id(ansible_module):
    """
    :Title: Test pki ca-user-cert-del, should not delete cert assigned to user with invalid certID
    :Description: Command should not delete certificate assigned to user using ca-user-cert-del.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. pki ca-user-cert-add <user> --serial <serial>
        2. pki ca-user-cert-del <user> <invalid_cert_id>
    :ExpectedResults:
        1. Command should not delete the certificate assigned to user with invalid certID
    :Automated: Yes
    """

    user = 'testuser0'
    fullName = 'Test User0'
    subject = 'UID={},CN={}'.format(user, fullName)
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')
    if cert_id:
        log.info("Generated certificate request with cert ID: {}".format(cert_id))
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
        add_cert_to_user(ansible_module, user, subject, cert_id, cert_subject)
        t = cert_subject
        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTPS_PORT,
                                     protocol='https',
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='{} "{}"'.format(user, t.replace('2;', '123;')))

        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Deleted certificate "{}"'.format(cert_subject) in result['stdout']
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()
            else:
                assert 'PKIException: Failed to modify user' in result['stderr']
                log.info("Successfully run: {}".format(result['cmd']))

        cmd_out = ansible_module.pki(cli='ca-user-cert-find',
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTPS_PORT,
                                     protocol='https',
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='{}'.format(user))
        for res in cmd_out.values():
            if res['rc'] == 0:
                assert 'Cert ID: {}'.format(cert_subject) in res['stdout']
                assert 'Serial Number: {}'.format(cert_id) in res['stdout']
                log.info("Successfully run: {}".format(res['cmd']))
            else:
                log.error("Failed to run: {}".format(res['cmd']))
                pytest.fail()
    else:
        log.error("Failed to generate certificate.")
        pytest.fail("")
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_cert_del_with_non_existing_user_id(ansible_module):
    """
    :Title: Test pki ca-user-cert-del, should if non-existing userID is provided.
    :Description: Command should not delete certificate insted it should fail if non-existing userID is provided.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. pki ca-user-cert-del non_exist_user <cert_id>
    :ExpectedResults:
        1. Verify whether pki ca-user-cert-del fail if non-existing certID is provided.
    :Automated: Yes
    """

    user = 'xyzuser'
    fullName = user

    subject = 'UID={},CN={}'.format(user, fullName)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')
    if cert_id:
        log.info("Generated certificate request with cert ID: {}".format(cert_id))
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)

        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTPS_PORT,
                                     protocol='https',
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='{} "{}"'.format(user, cert_subject))

        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Deleted certificate "{}"'.format(cert_subject) in result['stdout']
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()
            else:
                assert 'ResourceNotFoundException: User not found' in result['stderr']
                log.info("Successfully run: {}".format(result['cmd']))
    else:
        log.error("Failed to generate certificate.")
        pytest.fail("")


def test_pki_ca_user_cert_del_with_mismatch_of_user_id_cert_id(ansible_module):
    """
    :Title: Test pki ca-user-cert-del, should if there is mismatch of userID and certID.
    :Description: Command should fail and do not delete certificate if there is mismatch of
    userID and certID.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. pki ca-user-cert-del <cert_id> <user_id>
    :ExpectedResults:
        1. Verify whether pki ca-user-cert-del fail if there is mismatch of userID and certID.
    :Automated: Yes
    """

    user = 'tuser2'
    fullName = 'Test User 2'

    subject = 'UID={},CN={}'.format(user, fullName)
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')
    log.info("Generated certificate request with cert ID: {}".format(cert_id))

    if cert_id:
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
        add_cert_to_user(ansible_module, user, subject, cert_id, cert_subject)

        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTPS_PORT,
                                     protocol='https',
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='{} "{}"'.format(constants.CA_ADMIN_USERNAME,
                                                                 cert_subject))

        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Deleted certificate "{}"'.format(cert_subject) in result['stdout']
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()
            else:
                error = "PKIException: Failed to modify user"
                assert error in result['stderr']
                log.info("Successfully run: {}".format(result['cmd']))
    else:
        log.error("Failed to generate certificate.")
        pytest.fail("")


def test_pki_ca_user_cert_del_when_user_id_is_not_provided(ansible_module):
    """
    :Title: Test pki ca-user-cert-del, should if userID not provided.
    :Description: Command should fail if userID not provided.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. pki ca-user-cert-del <certid>
    :ExpectedResults:
        1. Verify whether pki ca-user-cert-del fail if userID not provided.
    :Automated: Yes
    """
    user = 'xyzuser'
    fullName = user
    subject = 'UID={},CN={}'.format(user, fullName)
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')
    log.info("Generated certificate request with cert ID: {}".format(cert_id))

    if cert_id:
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
        add_cert_to_user(ansible_module, user, subject, cert_id, cert_subject)

        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTPS_PORT,
                                     protocol='https',
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='{}'.format(cert_id))

        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Deleted certificate "{}"'.format(cert_subject) in result['stdout']
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()
            else:
                error = "Incorrect number of arguments specified."
                assert error in result['stderr']
                log.info("Successfully run: {}".format(result['cmd']))
    else:
        log.error("Failed to generate certificate.")
        pytest.fail("")


def test_pki_ca_user_cert_del_when_cert_id_is_not_provided(ansible_module):
    """
    :Title: Test pki ca-user-cert-del, should if certID not provided.
    :Description: Command should fail if certID not provided.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. pki ca-user-cert-del <userid>
    :ExpectedResults:
        1. Verify whether pki ca-user-cert-del fail if certID not provided.
    :Automated: Yes
    """
    user = 'testuser0'
    fullName = user
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
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()
        else:
            error = "Incorrect number of arguments specified."
            assert error in result['stderr']
            log.info("Successfully run: {}".format(result['cmd']))


@pytest.mark.parametrize("users", ['CA_AuditV', 'CA_AgentV'])
def test_pki_ca_user_cert_del_with_different_valid_users(ansible_module, users):
    """
    :Title: Test pki ca-user-cert-del, delete certs assigned to user using CA_AgentV should fail.
    :Description: Command should not able to delete certs assigned to user using CA_AgentV it
    should fail.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. pki -n CA_AgentV ca-user-cert-del <userid> <certid>
        2. pki -n CA_AuditV ca-user-cert-del <userid> <certid>
    :ExpectedResults:
        1. Verify whether pki ca-user-cert-del delete certs assigned to user using CA_AgentV should fail.
    :Automated: Yes
    """
    user = 'testuser0'
    fullName = 'Test User 0'

    subject = 'UID={},CN={}'.format(user, fullName)
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')
    log.info("Generated certificate request with cert ID: {}".format(cert_id))

    if cert_id:
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
        add_cert_to_user(ansible_module, user, subject, cert_id, cert_subject)
        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTPS_PORT,
                                     protocol='https',
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(users),
                                     extra_args='{} "{}"'.format(user, cert_subject))

        for result in cmd_out.values():
            if result['rc'] == 0:
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()
            else:
                error = "ForbiddenException: Authorization Error"
                assert error in result['stderr']
                log.info("Successfully run: {}".format(result['cmd']))
    else:
        log.error("Failed to generate certificate.")
        pytest.fail("")
    userop.remove_user(ansible_module, user)


@pytest.mark.parametrize("users", ['CA_AuditE', 'CA_AgentE', 'CA_AdminE'])
def test_pki_ca_user_cert_del_with_expired_user_certs(ansible_module, users):
    """
    :Title: pki ca-user-cert-del command, delete certs assigned to user using CA_AdminE should fail.
    :Description: Command should not able to delete certs assigned to user using CA_AdminE it
    should fail.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. pki -n CA_AdminE ca-user-cert-del <userid> <cert_id>
        2. pki -n CA_AuditE ca-user-cert-del <userid> <cert_id>
        3. pki -n CA_AgentE ca-user-cert-del <userid> <cert_id>
    :ExpectedResults:
        1. Command should not delete certs assigned to user using CA_AdminE.
        2. Command should not delete certs assigned to user using CA_AuditE.
        3. Command should not delete certs assigned to user using CA_AgentE.
    :Automated: Yes
    """

    user = 'testuser0'
    fullName = 'Test User 0'

    subject = 'UID={},CN={}'.format(user, fullName)
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')
    if cert_id:
        log.info("Generated certificate request with cert ID: {}".format(cert_id))
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
        add_cert_to_user(ansible_module, user, subject, cert_id, cert_subject)
        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTPS_PORT,
                                     protocol='https',
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(users),
                                     extra_args='{} "{}"'.format(user, cert_subject))

        for result in cmd_out.values():
            if result['rc'] == 0:
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()
            else:
                # Commenting redundant error messages
                # if 'CERTIFICATE_EXPIRED' in result['stderr']:
                #     error = "FATAL: SSL alert received: CERTIFICATE_EXPIRED\n" \
                #             "IOException: SocketException cannot write on socket"
                # else:
                #     error = "IOException: SocketException cannot write on socket"
                assert "SEVERE: FATAL: SSL alert received: CERTIFICATE_EXPIRED\nIOException: " \
                       "SocketException cannot read on socket: Error reading from socket: " \
                       "(-12269) SSL peer rejected your certificate as expired." in result['stderr']
                log.info("Successfully run: {}".format(result['cmd']))
    else:
        log.error("Failed to generate certificate.")
        pytest.fail("")
    userop.remove_user(ansible_module, user)


@pytest.mark.parametrize("users", ['CA_AuditR', 'CA_AgentR', 'CA_AdminR'])
def test_pki_ca_user_cert_del_with_revoked_certs(ansible_module, users):
    """
    :Test: pki ca-user-cert-del command, delete certs assigned to user using CA_AdminR should fail.
    :Description: Command should not able to delete certs assigned to user using CA_AdminR it should fail.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. pki -n CA_AuditR ca-user-cert-del <user> <certid>
        2. pki -n CA_AdminR ca-user-cert-del <user> <certid>
        3. pki -n CA_AgentR ca-user-cert-del <user> <certid>
    :ExpectedResults:
        1. Command should delete certs assigned to user using CA_AdminR should fail.
    :Automated: Yes
    """

    user = 'testuser0'
    fullName = 'Test User 0'

    subject = 'UID={},CN={}'.format(user, fullName)
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')
    log.info("Generated certificate request with cert ID: {}".format(cert_id))

    if cert_id:
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
        add_cert_to_user(ansible_module, user, subject, cert_id, cert_subject)
        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTPS_PORT,
                                     protocol='https',
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(users),
                                     extra_args='{} "{}"'.format(user, cert_subject))

        for result in cmd_out.values():
            if result['rc'] == 0:
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()
            else:
                error = "PKIException: Unauthorized"
                assert error in result['stderr']
                log.info("Successfully run: {}".format(result['cmd']))
    else:
        log.error("Failed to generate certificate.")
        pytest.fail("")
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_cert_del_with_ca_operatorv(ansible_module):
    """
    :Title: pki ca-user-cert-del command, delete certs assigned to user using CA_OperatorV should fail.
    :Description: Command should not able to delete certs assigned to user using CA_OperatorV it should fail.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1.
    :ExpectedResults:
        1. Command should not delete certs assigned to user using CA_OperatorV.
    :Automated: Yes
    """

    user = 'CA_OperatorV'
    fullName = 'CA OperatorV'
    group = 'Operator'
    subject = 'UID={},CN={}'.format(user, fullName)
    t_user = 'tuser28'
    t_fullName = 'Test user 28'
    t_subject = 'UID={},CN={}'.format(t_user, t_fullName)
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    userop.add_user(ansible_module, 'add', userid=t_user, user_name=t_fullName)

    group_add = basic_pki_cmd + " ca-group-add {} --description 'Operator Group'".format(group)
    user_add_to_group = basic_pki_cmd + " ca-user-membership-add {} {}".format(user, group)

    ansible_module.command(group_add)
    ansible_module.command(user_add_to_group)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')
    if cert_id:
        log.info("Generated certificate request with cert ID: {}".format(cert_id))
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
        add_cert_to_user(ansible_module, user, subject, cert_id, cert_subject)

        import_cert = ansible_module.command(basic_pki_cmd + " client-cert-import {} "
                                                             "--serial {}".format(user,
                                                                                  cert_id))
        for r in import_cert.values():
            if r['rc'] == 0:
                assert 'Imported certificate "{}"'.format(user) in r['stdout']
                log.info("Successfully run: {}".format(r['cmd']))
                log.info("Imported certificate '{}'".format(user))
            else:
                log.error("Failed to import certificate.")
                pytest.xfail()
    else:
        log.error("Failed to generate certificate")
        pytest.fail()

    t_cert_id = userop.process_certificate_request(ansible_module, subject=t_subject,
                                                   request_type='pkcs10', algo='rsa',
                                                   keysize='2048', profile='caUserCert')
    if t_cert_id:
        log.info("Generated certificate request with cert ID: {}".format(t_cert_id))
        t_cert_subject = "2;{};{};{}".format(int(t_cert_id, 16), CA_SUBJECT, t_subject)
        add_cert_to_user(ansible_module, t_user, t_subject, t_cert_id, t_cert_subject)

        t_cmd_out = ansible_module.pki(cli=pki_cmd,
                                       nssdb=constants.NSSDB,
                                       dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                       port=constants.CA_HTTPS_PORT,
                                       protocol='https',
                                       hostname=constants.MASTER_HOSTNAME,
                                       certnick='"{}"'.format(user),
                                       extra_args='{} "{}"'.format(t_user, t_cert_id))

        for result in t_cmd_out.values():
            if result['rc'] == 0:
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()
            else:
                error = "ForbiddenException: Authorization Error"
                assert error in result['stderr']
                log.info("Successfully run: {}".format(result['cmd']))
    else:
        log.error("Failed to generate certificate.")
        pytest.fail("")

    userop.remove_user(ansible_module, user)
    log.info("Removed user: {}".format(user))
    userop.remove_user(ansible_module, t_user)
    log.info("Removed user: {}".format(t_user))
    group_del = basic_pki_cmd + " ca-group-del Operator"
    ansible_module.command(group_del)
    log.info("Removed group: Operator")
    ansible_module.command(client_cert_del + " {}".format(user))
    log.info("Deleted the certificate: {}".format(user))


def test_pki_ca_user_cert_del_user_without_any_role(ansible_module):
    """
    :Title: pki ca-user-cert-del command, delete certs assigned to user - as a normal user.
    :Description: Command should not able to delete certs assigned to user - as a user not assigned to any
        role should fail.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. pki ca-user-cert-del <user> <certid>
    :ExpectedResults:
        1. Command should not delete the cert using normal user.
    :Automated: Yes
    """

    user = 'tuser3'
    fullName = 'Test User 3'
    subject = "UID={},CN={}".format(user, fullName)

    user2 = 'tuser101'
    fullName2 = 'Test {}'.format(user2)
    subject2 = 'UID={},CN={}'.format(user2, fullName2)

    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    userop.add_user(ansible_module, 'add', userid=user2, user_name=fullName2)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')

    if cert_id:
        log.info("Generated certificate request with cert ID: {}".format(cert_id))
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
        add_cert_to_user(ansible_module, user, subject, cert_id, cert_subject)

        import_cert = ansible_module.command(basic_pki_cmd + " client-cert-import {} "
                                                             "--serial {}".format(user, cert_id))
        for r in import_cert.values():
            if r['rc'] == 0:
                assert 'Imported certificate "{}"'.format(user) in r['stdout']
                log.info("Successfully run: {}".format(r['cmd']))
                log.info("Imported certificate '{}'".format(user))
            else:
                log.error("Failed to import certificate.")
                pytest.xfail()
    else:
        log.error("Failed to generate certificate.")
        pytest.fail("")

    t_cert_id = userop.process_certificate_request(ansible_module, subject=subject2,
                                                   request_type='pkcs10', algo='rsa',
                                                   keysize='2048', profile='caUserCert')
    if t_cert_id:
        log.info("Generated certificate request with cert ID: {}".format(t_cert_id))
        t_cert_subject = "2;{};{};{}".format(int(t_cert_id, 16), CA_SUBJECT, subject2)
        add_cert_to_user(ansible_module, user2, subject2, t_cert_id, t_cert_subject)

        t_cmd_out = ansible_module.pki(cli=pki_cmd,
                                       nssdb=constants.NSSDB,
                                       dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                       port=constants.CA_HTTPS_PORT,
                                       protocol='https',
                                       hostname=constants.MASTER_HOSTNAME,
                                       certnick='"{}"'.format(user),
                                       extra_args='{} "{}"'.format(user2, t_cert_subject))

        for result in t_cmd_out.values():
            if result['rc'] == 0:
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()
            else:
                error = "ForbiddenException: Authorization Error"
                assert error in result['stderr']
                log.info("Successfully run: {}".format(result['cmd']))
    else:
        log.error("Failed to generate certificate.")
        pytest.fail("")
    userop.remove_user(ansible_module, user)
    log.info("Removed user: {}".format(user))
    userop.remove_user(ansible_module, user2)
    log.info("Removed user: {}".format(user2))
    ansible_module.command(client_cert_del + " {}".format(user))
    log.info("Deleted the certificate: {}".format(user))


def test_pki_ca_user_cert_del_switching_the_positions_of_req_options(ansible_module):
    """
    :Title: pki ca-user-cert-del command, delete certs assigned to user - switch positions of
    required options.
    :Description: Command should not able to delete certs assigned to user - switch positions of required options.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. pki ca-user-cert-del <cert_id> <userid>
    :ExpectedResults:
        1. It should throw an error
    :Automated: Yes
    """

    user = 'testuser0'
    fullName = 'Test User 3'
    subject = "UID={},CN={}".format(user, fullName)
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')
    if cert_id:
        log.info("Generated certificate request with cert ID: {}".format(cert_id))
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
        add_cert_to_user(ansible_module, user, subject, cert_id, cert_subject)

        t_cmd_out = ansible_module.pki(cli=pki_cmd,
                                       nssdb=constants.NSSDB,
                                       dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                       port=constants.CA_HTTPS_PORT,
                                       protocol='https',
                                       hostname=constants.MASTER_HOSTNAME,
                                       certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                       extra_args='"{}" {}'.format(cert_subject, user))

        for result in t_cmd_out.values():
            if result['rc'] == 0:
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()
            else:
                error = "PKIException: Internal Server Error"
                assert error in result['stderr']
                log.info("Successfully run: {}".format(result['cmd']))
    else:
        log.error("Failed to generate certificate.")
        pytest.fail("")
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_cert_del_when_admin_user_cert_is_deleted(ansible_module):
    """
    :Title: Test pki ca-user-cert-del, add Admin user, add a cert to Admin user,
    add a new user as Admin user, delete the cert assigned to Admin user, and then adding a
    new user should fail.
    :Description: add Admin user, add a cert to Admin user, add a new user as Admin user,
    delete the cert assigned to Admin user, and then adding a new user should fail.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults:
        1. Verify whether adding admin user should fail if admin user certificate is removed.
    :Automated: Yes
    """

    admin_user = 'admin_user'
    admin_fullName = 'Admin User'
    user1 = 'tuser4'
    user1_fullName = 'Test User 4'
    user2 = 'tuser5'
    user2_fullName = 'Test User 5'
    subject = 'UID={},CN={}'.format(admin_user, admin_fullName)
    userop.add_user(ansible_module, 'add', userid=admin_user, user_name=admin_fullName)
    log.info("Added user {}".format(admin_user))
    group_add = basic_pki_cmd + " ca-group-member-add Administrators {}".format(admin_user)
    group_out = ansible_module.command(group_add)
    for result in group_out.values():
        assert result['rc'] == 0
        log.info("Added {} to Administrator".format(admin_user))

    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')
    if cert_id:
        log.info("Generated certificate request with cert ID: {}".format(cert_id))
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
        add_cert_to_user(ansible_module, admin_user, subject, cert_id, cert_subject)

        import_cert = ansible_module.command(basic_pki_cmd + " client-cert-import {} "
                                                             "--serial {}".format(admin_user,
                                                                                  cert_id))
        for r in import_cert.values():
            if r['rc'] == 0:
                assert 'Imported certificate "{}"'.format(admin_user) in r['stdout']
                log.info("Successfully run: {}".format(r['cmd']))
                log.info('Imported certificate "{}"'.format(admin_user))
            else:
                log.error("Failed to import certificate.")
                pytest.xfail()
        add_user = ansible_module.pki(cli='ca-user-add',
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.CA_HTTPS_PORT,
                                      protocol='https',
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(admin_user),
                                      extra_args='{}  --fullName "{}"'.format(user1,
                                                                              user1_fullName))

        for result in add_user.values():
            assert result['rc'] == 0
            log.info("Running: {}".format(result['cmd']))
            log.info("Added user {} using {}".format(user1, admin_user))
        add_user = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.CA_HTTPS_PORT,
                                      protocol='https',
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                      extra_args='{} "{}"'.format(admin_user, cert_subject))

        for result in add_user.values():
            assert result['rc'] == 0
            log.info("Running: {}".format(result['cmd']))
            log.info("Deleted {}'s certificate \"{}\"".format(admin_user, cert_subject))

        add_user = ansible_module.pki(cli='ca-user-add',
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.CA_HTTPS_PORT,
                                      protocol='https',
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(admin_user),
                                      extra_args='{}  --fullName "{}"'.format(user2,
                                                                              user2_fullName))

        for result in add_user.values():
            if result['rc'] == 0:
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()
            else:
                assert "PKIException: Unauthorized" in result['stderr']
                log.info("Successfully run: {}".format(result['cmd']))

    for u in [user1, user2]:
        userop.remove_user(ansible_module, user1)
        log.info("Removed user: {}".format(u))
    userop.remove_user(ansible_module, admin_user)
    ansible_module.command(client_cert_del + " {}".format(admin_user))


def test_pki_ca_user_cert_delete_when_agent_user_cert_is_deleted(ansible_module):
    """
    :Title: Test pki ca-user-cert-del, add Agent user, add a cert to Agent user,
    approve a cert request as Agent user, delete the cert from the Agent user and approving a
    new cert request should fail.
    :Description: add Agent user, add a cert to Agent user, approve a cert request as Agent
    user, delete the cert from the Agent user and approving a new cert request should fail.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add user to CMA Group.
        2. Issue the certificate to the agent user.
        3. Add user using newly create agent user.
        4. Remove admin user certificate.
        5. Issue new certificate using agent user.
    :ExpectedResults:
        1. Issueing certificate using new admin should fail if certificate is not assigned
        to agentuser.
    :Automated: Yes
    """

    agent_user = 'agent_user'
    agent_fullName = 'agent User'

    subject = 'UID={},CN={}'.format(agent_user, agent_fullName)
    userop.add_user(ansible_module, 'add', userid=agent_user, user_name=agent_fullName)

    group_add = basic_pki_cmd + " ca-group-member-add " \
                                "'Certificate Manager Agents' {}".format(agent_user)
    group_out = ansible_module.command(group_add)
    for result in group_out.values():
        assert result['rc'] == 0

    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')
    log.info("Generated certificate request with cert ID: {}".format(cert_id))

    if cert_id:
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
        add_cert_to_user(ansible_module, agent_user, subject, cert_id, cert_subject)

        import_cert = ansible_module.command(basic_pki_cmd + " client-cert-import {} "
                                                             "--serial {}".format(agent_user,
                                                                                  cert_id))
        for r in import_cert.values():
            if r['rc'] == 0:
                assert 'Imported certificate "{}"'.format(agent_user) in r['stdout']
                log.info("Successfully run: {}".format(r['cmd']))
                log.info('Imported certificate "{}"'.format(agent_user))
            else:
                log.error("Failed to import certificate.")
                pytest.xfail()

        new_cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                         request_type='pkcs10', algo='rsa',
                                                         approver_nickname=agent_user,
                                                         keysize='2048', profile='caUserCert')
        log.info("Generated certificate request with cert ID: {}".format(new_cert_id))

        assert new_cert_id

        del_cert = ansible_module.pki(cli='ca-user-cert-del',
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.CA_HTTPS_PORT,
                                      protocol='https',
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                      extra_args='{}  "{}"'.format(agent_user, cert_subject))

        for result in del_cert.values():
            assert result['rc'] == 0

        new_cert_id2 = userop.process_certificate_request(ansible_module, subject=subject,
                                                          request_type='pkcs10', algo='rsa',
                                                          approver_nickname=agent_user,
                                                          keysize='2048', profile='caUserCert')
        log.info("Generated certificate request with cert ID: {}".format(new_cert_id2))

        assert new_cert_id2 == None
    userop.remove_user(ansible_module, agent_user)
    log.info("Removed user: {}".format(agent_user))
    ansible_module.command(client_cert_del + " {}".format(agent_user))
