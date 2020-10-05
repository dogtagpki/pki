#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI CA-USER-DEL CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki user commands needs to be tested:
#   pki ca-user-del
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
import subprocess
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
logging.basicConfig(stream=sys.stdout)
TOPOLOGY = constants.CA_INSTANCE_NAME.split("-")[1]

pki_cmd = "ca-user-del"
if TOPOLOGY != '01':
    CA_SUBJECT = 'CN=CA Signing Certificate,OU={},O={}'.format(constants.CA_INSTANCE_NAME,
                                                               constants.CA_SECURITY_DOMAIN_NAME)
else:
    CA_SUBJECT = 'CN=CA Signing Certificate,OU={},O={}'.format('pki-tomcat',
                                                               constants.CA_SECURITY_DOMAIN_NAME)

basic_pki_cmd = 'pki -d {} -c {} -p {} -P {} -n "{}"'.format(constants.NSSDB,
                                                       constants.CLIENT_DIR_PASSWORD,
                                                       constants.CA_HTTP_PORT,
                                                       constants.PROTOCOL_UNSECURE,
                                                       constants.CA_ADMIN_NICK)
user_add = 'pki -d {} -c {} -p {} -P {} -n "{}" ' \
           'ca-user-add '.format(constants.NSSDB, constants.CLIENT_DIR_PASSWORD,
                                 constants.CA_HTTP_PORT, constants.PROTOCOL_UNSECURE,
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


@pytest.mark.parametrize('args', ['--help', ''])
def test_pki_ca_user_del_help_command(ansible_module, args):
    """
    :Title: Test pki ca-user-del with --help option.
    :Description: Command should show the following options.
            usage: ca-user-del <User ID> [OPTIONS...]
                --help   Show help options
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. pki ca-user-del --help
        2. pki ca-user-del
        3. pki ca-user-del sfsaf
    :ExpectedResults:
        1. It will show help option
        2. It wll throw an error.
        3. It will throw an error
    :CaseComponent: \-
    :Automated: Yes
    """
    cmd = 'pki {} {}'.format(pki_cmd, args)
    cmd_out = ansible_module.command(cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "usage: {} <User ID> [OPTIONS...]".format(pki_cmd) in result['stdout']
            assert re.search("--help\s+Show help message.", result['stdout'])
            log.info('Successfully ran : {}'.format(result['cmd']))
        elif args == '':
            assert 'No User ID specified.' in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))


@pytest.mark.parametrize('users', ["ca_agent1", "abcdefghijklmnopqrstuvwxyx12345678",
                                   "abc#", "0"])
def test_pki_ca_user_del_delete_valid_users(ansible_module, users):
    """
    :Title: Test pki ca-user-del, command should delete the users.
    :Description: Command should delete the users which are added to the system.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add user ca_agent1 and delete it.
        2. Add user abcdefghijklmnopqrstuvwxyz123456789 and delete it.
        3. Add user abc# and delete it.
        4. Add user 0 and delete it.
    :ExpectedResults:
        1. Verify ca-user-del should delete user in the system.
    :CaseComponent: \-
    :Automated: Yes
    """

    user = users
    full_name = 'Name {}'.format(user)

    userop.add_user(ansible_module, 'add', user_name=full_name, userid=user)
    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(user))
    for res in cmd_out.values():
        if res['rc'] == 0:
            assert 'Deleted user "{}"'.format(user) in res['stdout']
            log.info('Successfully ran: {}'.format(res['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()


def test_pki_ca_user_del_with_invalid_user(ansible_module):
    """
    :Title: Test pki ca-user-del with invalid user
    :Description: Test pki ca-user-del with invalid user
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki ca-user-del <invalid_user>
    :ExpectedResults:
        1. It should throw an exception.
    :Automated: Yes
    """
    user = 'asdfa'
    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(user))
    for res in cmd_out.values():
        if res['rc'] == 0:
            assert 'Deleted user "{}"'.format(user) in res['stdout']
            log.error("Failed to run: {}".format(res['cmd']))
            pytest.fail()
        else:
            assert "ResourceNotFoundException: No such object" in res['stderr']
            log.info('Successfully ran : {}'.format(res['cmd']))


def test_pki_ca_user_del_with_case_sensitive_user_id(ansible_module):
    """
    :Title: Test pki ca-user-del, command test with case sensitive user id.
    :Description: Command should delete the users which are added to the system.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults:
        1. Verify whether pki ca-user-del should not delete the user with case sensitive username.
    :CaseComponent: \-
    :Automated: Yes
    """
    user = 'ca_agent2'
    full_name = 'Name {}'.format(user)

    userop.add_user(ansible_module, 'add', userid=user, user_name=full_name)
    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(user.upper()))
    for res in cmd_out.values():
        if res['rc'] == 0:
            assert 'Deleted user "{}"'.format(user.upper()) in res['stdout']
            log.info('Successfully ran : {}'.format(res['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()


@pytest.mark.parametrize('user_id', ["2047", "2047_symb"])
def test_pki_ca_user_del_max_len_user_id(user_id, ansible_module):
    """
    :Title: Test pki ca-user-del, command test with max len of user id.
    :Description: Command should delete the users which are added userid as max length .
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults:
        1. Verify whether pki user-del should delete the user with user id as max length.
    :CaseComponent: \-
    :Automated: Yes
    """
    user = ''
    if user_id.startswith('2047'):
        rand = subprocess.check_output(['openssl', 'rand', '-base64', '2047'])
        user = filter(str.isalnum, rand)
        if user_id.endswith('_symb'):
            user += "!?@~#*^_+$"
    full_name = 'User {}'.format(user_id)

    userop.add_user(ansible_module, 'add', userid=user, user_name=full_name)

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(user))
    for res in cmd_out.values():
        if res['rc'] == 0:
            assert 'Deleted user "{}"'.format(user) in res['stdout']
            log.info('Successfully ran : {}'.format(res['cmd']))
        else:
            log.error("Failed to run: {}".format(res['cmd']))
            pytest.fail()


def test_pki_ca_user_del_user_with_all_attributes(ansible_module):
    """
    :Title: Test pki ca-user-del, command test delete user with all attribute and certificate.
    :Description: Command should delete the user with all attribute and certificate.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add user with all attributes and delete it.
    :ExpectedResults:
        1. Verify whether pki user-del should delete the user who has all attribute and certificate.
    :CaseComponent: \-
    :Automated: Yes
    """

    user = "tusr1{}".format(str(random.randint(111, 99999)))
    email = "{}@myemail.com".format(user)
    user_password = "agent2Password"
    phone = "1234567890"
    state = "NC"
    type = "Administrators"
    gid = "Administrators"
    full_name = 'CA OperatorV'
    subject = 'UID={},CN={}'.format(user, full_name)

    userop.add_user(ansible_module, 'add', userid=user, user_name=full_name, email=email,
                    password=user_password, phone=phone, state=state, type=type)
    user_add_to_group = basic_pki_cmd + " ca-user-membership-add {} {}".format(user, gid)
    membership_out = ansible_module.command(user_add_to_group)
    for res in membership_out.values():
        if res['rc'] == 0:
            assert 'Added membership in "{}"'.format(gid) in res['stdout']
        else:
            log.error("Failed to add into group.")
            pytest.fail("")

    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 profile='caUserCert',
                                                 keysize=2048)
    if cert_id:
        log.info("Generated certificate with cert ID: {}".format(cert_id))
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
        add_cert_to_user(ansible_module, user, subject, cert_id, cert_subject)

    user_del_out = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.CA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                      extra_args='{}'.format(user))
    for result in user_del_out.values():
        if result['rc'] == 0:
            assert 'Deleted user "{}"'.format(user) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()


@pytest.mark.parametrize("users", ['CA_AdminR', 'CA_AgentR'])
def test_pki_ca_user_del_user_using_revoked_cert(ansible_module, users):
    """
    :Title: Test pki ca-user-del, command test delete user using revoked admin certificate.
    :Description: Command should delete the user with revoked admin certificate.
    :Requirement:
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. pki -n CA_AdminR ca-user-del testuser1
        2. pki -n CA_AgentR ca-user-del testuser1
    :ExpectedResults:
        1. Verify whether pki user-del should delete the user with revoked admin certificate.
    :CaseComponent: \-
    :Automated: Yes
    """

    user = 'TestR3{}'.format(random.randint(111, 9999))
    full_name = 'User {}'.format(user)
    userop.add_user(ansible_module, 'add', user_id=user, user_name=full_name)

    user_del_out = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.CA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(users),
                                      extra_args='{}'.format(user))
    for result in user_del_out.values():
        if result['rc'] == 0:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()
            assert 'Deleted user "{}"'.format(user) in result['stdout']
        else:
            assert "PKIException: Unauthorized" in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
    userop.remove_user(ansible_module, user=user)


@pytest.mark.parametrize('users', ['CA_AgentV', 'CA_AuditV'])
def test_pki_ca_user_del_user_using_valid_agent_audit_cert(ansible_module, users):
    """
    :Title: Test pki ca-user-del, command should not delete the user using valid agent certificate.
    :Description: Command should not delete the user using valid agent certificate.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. pki -n CA_AgentV ca-user-del
        2. pki -n CA_AuditV ca-user-del
    :ExpectedResults:
        1. Verify whether pki user-del should not delete the user using valid agent certificate.
    :CaseComponent: \-
    :Automated: Yes
    """

    user = 'TestV3{}'.format(random.randint(111, 9999))
    full_name = 'User {}'.format(user)

    userop.add_user(ansible_module, 'add', user_id=user, user_name=full_name)

    user_del_out = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.CA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(users),
                                      extra_args='{}'.format(user))
    for result in user_del_out.values():
        if result['rc'] == 0:
            log.error('Failed to run : {}'.format(result['cmd']))
            assert 'Deleted user "{}"'.format(user) in result['stdout']
            pytest.fail()

        else:
            assert "ForbiddenException: Authorization Error" in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
    userop.remove_user(ansible_module, user=user)


@pytest.mark.parametrize('users', ['CA_AgentE', 'CA_AdminE'])
def test_pki_ca_user_del_user_using_expired_admin_cert(ansible_module, users):
    """
    :Title: Test pki ca-user-del, command should not delete the user using expired admin certificate.
    :Description: Command should delete the users using expired admin certificate.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. pki -n CA_AgentE ca-user-del
        2. pki -n CA_AdminE ca-user-del
    :ExpectedResults:
        1. Verify whether pki user-del should not delete the user using expired admin certificate.
    :CaseComponent: \-
    :Automated: Yes
    """

    user = 'TestE3{}'.format(random.randint(111, 9999))
    full_name = 'User {}'.format(user)
    userop.add_user(ansible_module, 'add', user_id=user, user_name=full_name)

    user_del_out = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.CA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(users),
                                      extra_args='{}'.format(user))
    for result in user_del_out.values():
        if result['rc'] == 0:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()
            assert 'Deleted user "{}"'.format(user) in result['stdout']
        else:
            assert "SEVERE: FATAL: SSL alert received: CERTIFICATE_EXPIRED\nIOException: " \
                   "SocketException cannot read on socket: Error reading from socket: " \
                   "(-12269) SSL peer rejected your certificate as expired." in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
    userop.remove_user(ansible_module, user=user)


@pytest.mark.parametrize('users', ['CA_OperatorV'])
def test_pki_ca_user_del_user_with_valid_operator_cert(ansible_module, users):
    """
    :Title: Test pki ca-user-del, command should not delete the user using valid operator certificate.
    :Description: Command should not delete the users using valid operator certificate.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add operator user, add user to operator group.
        2. Issue the certificate and add certificate to the user.
        3. Import operator user to the client database.
        4. Delete user using operator user.
    :ExpectedResults:
        1. Verify whether pki user-del should not delete the user valid operator certificate.
    :CaseComponent: \-
    :Automated: Yes
    """

    user = users
    fullName = 'CA OperatorV'
    t_user = 'TestE3{}'.format(random.randint(111, 9999))
    t_full_name = 'User {}'.format(t_user)
    group = 'Operator'
    subject = 'UID={},CN={}'.format(user, fullName)
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

    user_del_out = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.CA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(user),
                                      extra_args='{}'.format(t_user))
    for result in user_del_out.values():
        if result['rc'] == 0:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()
            assert 'Deleted user "{}"'.format(user) in result['stdout']
        else:
            error = "ForbiddenException: Authorization Error"
            assert error in result['stderr']
            log.info('Successfully ran pki -n {} user-del {}.'.format(users, user))
    userop.remove_user(ansible_module, user)
    userop.remove_user(ansible_module, t_user)
    ansible_module.command(group_del + group)
    ansible_module.command(client_cert_del + '"{}"'.format(user))


def test_pki_ca_user_del_user_using_user_cert(ansible_module):
    """
    :Title: Test pki ca-user-del, command should not delete the user using user cert.
    :Description: Command should not delete the users using user cert.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add user
        2. Issue certificate and add it to the user.
        3. Import certificate to the client database.
        4. Add new user using existing user.
    :ExpectedResults:
        1.Verify whether pki user-del should not delete the user using user cert.
    :CaseComponent: \-
    :Automated: Yes
    """
    user = 'tuser1{}'.format(str(random.randint(111, 999999)))
    full_name = "User {}".format(user)
    t_user = 'tuser2{}'.format(str(random.randint(111, 999999)))
    t_full_name = "User {}".format(t_user)
    userop.add_user(ansible_module, 'add', userid=user, user_name=full_name)

    subject = 'UID={},CN={}'.format(user, full_name)

    cert_id = userop.process_certificate_request(ansible_module, subject=subject, profile='caUserCert', keysize=2048)
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
                log.error("Failed to import certificate.")
                pytest.fail()

    user_del_out = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.CA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(user),
                                      extra_args='{}'.format(t_user))
    for result in user_del_out.values():
        if result['rc'] == 0:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()
            assert 'Deleted user "{}"'.format(user) in result['stdout']
        else:
            error = "ForbiddenException: Authorization Error"
            assert error in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
    userop.remove_user(ansible_module, user)
    ansible_module.command('pki -d {} -c {} client-cert-del '
                           '{}'.format(constants.NSSDB, constants.CLIENT_DIR_PASSWORD, user))
