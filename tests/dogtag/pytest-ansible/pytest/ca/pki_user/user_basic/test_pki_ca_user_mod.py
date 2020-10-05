#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI CA-USER-MOD CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki user commands needs to be tested:
#   pki ca-user-mod
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

pki_cmd = "ca-user-mod"
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
def test_pki_ca_user_mod_help(ansible_module, args):
    """
    :Title: test pki ca-user-mod --help and pki ca-user-mod --help command
    :Description: Command should successfully show its option for pki ca-user-mod command
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-user-mod --help
        2. Run pki ca-user-mod ''
    :ExpectedResults:
        1. It should shows it's options correctly.
        2. It will throw an error.
    :Automated: Yes
    """
    user_mod = 'pki {} {}'.format(pki_cmd, args)
    cmd_out = ansible_module.command(user_mod)
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "usage: {} <User ID> [OPTIONS...]".format(pki_cmd) in result['stdout']
            assert "--email <email>         Email" in result['stdout']
            assert "--fullName <fullName>   Full name" in result['stdout']
            assert "--help                  Show help message" in result['stdout']
            assert "--password <password>   Password" in result['stdout']
            assert "--phone <phone>         Phone" in result['stdout']
            assert "--state <state>         State" in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        elif args == '':
            assert 'No User ID specified.' in result['stderr']
        else:
            log.info('Failed to run: {}'.format(result['cmd']))
            pytest.fail('Failed to run: {}'.format(result['cmd']))


def test_pki_ca_user_mod_modify_user_full_name(ansible_module):
    """
    :Title: test pki ca-user-mod <user> --fullName command.
    :Description: Command should successfully modify the user's fullName.
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. pki ca-user-mod <user_id> --fullName <FullName>
    :ExpectedResults:
        1. Verify whether pki ca-user-mod <user> --fullName modify the user's full name.
    :Automated: Yes
    """
    user = "ca_agent2"
    fullName = "Test ca agent"
    mod_fullname = "Test ca agent Modified"

    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --fullName "{}"'.format(user, mod_fullname))

    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Modified user "{}"'.format(user) in result['stdout']
            assert 'User ID: {}'.format(user) in result['stdout']
            assert 'Full name: {}'.format(mod_fullname) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail("")
    userop.remove_user(ansible_module, user=user)


def test_pki_ca_user_mod_modify_users_details(ansible_module):
    """
    :Title: test pki ca-user-mod, Modify user's email, phone, state and password.
    :Description: Command should successfully modify the user's email, phone, state and password details.
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. pki ca-user-mod <userid> --email <email> --phone <phone> --state <state> --password<passowrd>
    :ExpectedResults:
        1. Verify whether pki ca-user-mod modify the user's full name, phone, state, email, password.
    :Automated: Yes
    """
    user = "ca_agent2"
    fullName = "Test ca agent"
    user_mod_email = "testcaagent@myemail.com"
    user_mod_passwd = "Secret1234"
    user_mod_state = "NC"
    user_mod_phone = "1234567890"
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 hostname=constants.MASTER_HOSTNAME,
                                 port=constants.CA_HTTP_PORT,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --email "{}" --phone {} --state {} '
                                            '--password {}'.format(user, user_mod_email,
                                                                   user_mod_phone, user_mod_state,
                                                                   user_mod_passwd))

    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Modified user "{}"'.format(user) in result['stdout']
            assert 'User ID: {}'.format(user) in result['stdout']
            assert 'Full name: {}'.format(fullName) in result['stdout']
            assert 'Email: {}'.format(user_mod_email) in result['stdout']
            assert 'State: {}'.format(user_mod_state) in result['stdout']
            assert 'Phone: {}'.format(user_mod_phone) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail("")
    userop.remove_user(ansible_module, user=user)


@pytest.mark.parametrize("email_id", ['abcdefghijklmnopqrstuvwxyx12345678', '#', '0',
                                      "2047", "2047_symb"])
def test_pki_ca_user_mod_email_with_chars_and_numbers(ansible_module, email_id):
    """
    :Title: test pki ca-user-mod <user> --email, modify user's email with characters and numbers.
    :Description: Command should successfully modify the user's email with characters and numbers.
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-user-mod <userid> --email abcdefghijklmnopqrstuvwxyx12345678
        2. Run pki ca-user-mod <userid> --email #
        3. Run pki ca-user-mod <userid> --email 0
        4. Run pki ca-user-mod <userid> --email 2047 char len + symbols
        5. Run pki ca-user-mod <userid> --email 2047 char len
    :ExpectedResults:
        1. Command should modified user's email with characters and numbers.
    :Automated: Yes
    """
    user = 'u1'
    fullName = 'Test u1'
    email = ''
    if email_id.startswith('2047'):
        rand = subprocess.check_output(['openssl', 'rand', '-base64', '2047'])
        email = filter(str.isalnum, rand)
        if email_id.endswith('_symb'):
            email += "!?@~#*^_+$"
    else:
        email = email_id
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --email "{}"'.format(user, email))

    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Modified user "{}"'.format(user) in result['stdout']
            assert 'User ID: {}'.format(user) in result['stdout']
            assert 'Full name: {}'.format(fullName) in result['stdout']
            assert 'Email: {}'.format(email) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail("")
    userop.remove_user(ansible_module, user=user)


@pytest.mark.parametrize("state", ['abcdefghijklmnopqrstuvwxyx12345678', '#', '0',
                                   "2047", "2047_symb"])
def test_pki_ca_user_mod_state_with_char_numbers(ansible_module, state):
    """
    :Title: test pki ca-user-mod <user> --state, Modify user's state with char and numbers.
    :Description: Command should successfully modify the user's state with char and numbers.
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults: 
        1. Verify whether pki ca-user-mod <user> --state, verify state is modified with
            char and numbers.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'u2'
    fullName = 'Test u2'
    st = ''
    if state.startswith('2047'):
        rand = subprocess.check_output(['openssl', 'rand', '-base64', '2047'])
        st = filter(str.isalnum, rand)
        if state.endswith('_symb'):
            st += "!?@~#*^_+$"
    else:
        st = state
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --state "{}"'.format(user, st))

    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Modified user "{}"'.format(user) in result['stdout']
            assert 'User ID: {}'.format(user) in result['stdout']
            assert 'Full name: {}'.format(fullName) in result['stdout']
            assert 'State: {}'.format(st) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail("")
    userop.remove_user(ansible_module, user=user)


@pytest.mark.parametrize("phone_id", ['abcdefghijklmnopqrstuvwxyx12345678',
                                      '#', '0', "2047", "2047_symb", "-1234"])
def test_pki_ca_user_mod_phone_with_chars_and_numbers(ansible_module, phone_id):
    """
    :Title: test pki ca-user-mod <user> --phone, modify user's phone with chars and numbers.
    :Description: Command should successfully modify the user's phone with chars and numbers.
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults: 
        1. Verify whether pki ca-user-mod <user> --phone is modified as chars and numbers.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'u3'
    fullName = 'Test {}'.format(user)
    phone = ''
    if phone_id.startswith('2047'):
        rand = subprocess.check_output(['openssl', 'rand', '-base64', '2047'])
        phone = filter(str.isalnum, rand)
        if phone_id.endswith('_symb'):
            phone += "!?@~#*^_+$"
    else:
        phone = phone_id
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --phone "{}"'.format(user, phone))

    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Modified user "{}"'.format(user) in result['stdout']
            assert 'User ID: {}'.format(user) in result['stdout']
            assert 'Full name: {}'.format(fullName) in result['stdout']
            if phone_id == '-1234':
                assert 'Phone: {}'.format(phone[1:]) in result['stdout']
            else:
                assert 'Phone: {}'.format(phone) in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        elif phone_id in ['#', '2047_symb']:
            assert "BadRequestException: Invalid attribute syntax" in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail("")
    userop.remove_user(ansible_module, user=user)


def test_pki_ca_user_mod_without_user_id(ansible_module):
    """
    :Title: test pki ca-user-mod without user id.
    :Description: Command should successfully modify the user without user id.
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. pki ca-user-mod --fullName
    :ExpectedResults:
        1. Command should not get executed and throws the error.
    :Automated: Yes
    """

    user1_fullName = "Test ca agent"
    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='--fullName "{}"'.format(user1_fullName))

    for result in cmd_out.values():
        if result['rc'] == 0:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail("")
        else:
            assert "No User ID specified." in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))


def test_pki_ca_user_mod_with_all_options(ansible_module):
    """
    :Title: test pki ca-user-mod <user> with it's all options.
    :Description: Command should successfully modify the user with it's all options.
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. pki ca-user-mod with all options
    :ExpectedResults:
        1. Verify whether pki ca-user-mod <user> with it's all options.
    :Automated: Yes
    """
    user = 'u3'
    fullName = "Test {} {}".format(user, str(random.randint(1111, 99999)))
    email = "u3{}@example.com".format(str(random.randint(111, 999999)))
    user_password = "agent2Password"
    phone = "1234567890"
    state = "NC" + str(random.randint(111, 999999))
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --email "{}" --phone {} --state {} '
                                            '--password {}'.format(user, email, phone, state,
                                                                   user_password))

    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Modified user "{}"'.format(user) in result['stdout']
            assert 'User ID: {}'.format(user) in result['stdout']
            assert 'Full name: {}'.format(fullName) in result['stdout']
            assert 'Email: {}'.format(email) in result['stdout']
            assert 'State: {}'.format(state) in result['stdout']
            assert 'Phone: {}'.format(phone) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail("")
    userop.remove_user(ansible_module, user=user)


def test_pki_ca_user_mod_with_short_pass(ansible_module):
    """
    :Title: test pki ca-user-mod <user> --password with the short password.
    :Description: Command should should not modify the user password with short password.
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. pki ca-user-mod <user> --password pas
    :ExpectedResults:
        1. user should not get modified with the short password.
    :Automated: Yes
    """

    user = 'u4'
    fullName = "Test {} {}".format(user, str(random.randint(1111, 99999)))
    password = "pass"
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --password {}'.format(user, password))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Modified user "{}"'.format(user) in result['stdout']
            assert 'User ID: {}'.format(user) in result['stdout']
            assert 'Full name: {}'.format(fullName) in result['stdout']
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail("")
        else:
            error = "PKIException: The password must be at least 8 characters"
            assert error in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))

    userop.remove_user(ansible_module, user=user)


@pytest.mark.parametrize('users', ['CA_AgentV', 'CA_AuditV'])
def test_pki_ca_user_mod_with_valid_non_admin_certs(ansible_module, users):
    """
    :Title: test pki ca-user-mod with valid Certificate CA_AgentV and CA_AuditV.
    :Description: Command should should not modify the user with non admin valid certificate
                  like CA_AgentV and CA_AuditV.
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. pki -n CA_AdminV ca-usermod <userid> --fullname <FullName>
        2. pki -n CA_AuditV ca-usermod <userid> --fullname <FullName>
    :ExpectedResults:
        1. Command should not modified the user with non admin valid certificates.
        2. Command should not modified the user with non admin valid certificates.
    :Automated: Yes
    """
    user = 'u5'
    fullName = "Test {} {}".format(user, str(random.randint(1111, 99999)))
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(users),
                                 extra_args='{} --fullName "{}"'.format(user, fullName + "test"))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Modified user "{}"'.format(user) in result['stdout']
            assert 'User ID: {}'.format(user) in result['stdout']
            assert 'Full name: {}'.format(fullName) in result['stdout']
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail("")
        else:
            error = "ForbiddenException: Authorization Error"
            assert error in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
    userop.remove_user(ansible_module, user=user)


@pytest.mark.parametrize('users', ['CA_AdminR', 'CA_AgentR'])
def test_pki_ca_user_mod_with_revoked_certs(ansible_module, users):
    """
    :Title: test pki ca-user-mod with revoked Certificates CA_AgentR, CA_AdminR.
    :Description: Command should should not modify the user with revoked certificate.
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults: 
        1. Verify whether pki ca-user-mod <user> should not modified the user with revoked certificates.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'u6'
    fullName = "Test {} {}".format(user, str(random.randint(1111, 99999)))
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(users),
                                 extra_args='{} --fullName {}'.format(user, fullName + " test"))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Modified user "{}"'.format(user) in result['stdout']
            assert 'User ID: {}'.format(user) in result['stdout']
            assert 'Full name: {}'.format(fullName) in result['stdout']
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail("")
        else:
            error = "PKIException: Unauthorized"
            assert error in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
    userop.remove_user(ansible_module, user=user)


@pytest.mark.parametrize('users', ['CA_AdminE', 'CA_AgentE'])
def test_pki_ca_user_mod_with_expired_certs(ansible_module, users):
    """
    :Title: test pki ca-user-mod with expired Certificates like CA_AdminE, CA_AgentE.
    :Description: Command should should not modify the user with expired certificate.
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults: 
        1. Verify whether pki ca-user-mod <user> should not modified the user with expired certificate, 
            It should throws the error.
    :Automated: Yes
    :CaseComponent: \-
    """

    user = 'u7'
    fullName = "Test {} {}".format(user, str(random.randint(1111, 99999)))
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(users),
                                 extra_args='{} --fullName "{}"'.format(user,
                                                                        "Test {}".format(user)))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Modified user "{}"'.format(user) in result['stdout']
            assert 'User ID: {}'.format(user) in result['stdout']
            assert 'Full name: {}'.format(fullName) in result['stdout']
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail("")
        else:
            assert "SEVERE: FATAL: SSL alert received: CERTIFICATE_EXPIRED\nIOException: " \
                   "SocketException cannot read on socket: Error reading from socket: " \
                   "(-12269) SSL peer rejected your certificate as expired." in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
    userop.remove_user(ansible_module, user=user)


def test_pki_ca_user_mod_with_valid_operator(ansible_module):
    """
    :Title: test pki ca-user-mod with valid Operator Certificate 'CA_OperatorV'.
    :Description: Command should should not modify the user with valid certificate.
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults: 
        1. Verify whether pki ca-user-mod <user> should not modified the user with valid Operator user certificate.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'u8'
    fullName = "Test {} {} ".format(user, str(random.randint(1111, 99999)))
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    user = "CA_OperatorV"
    fullName = 'CA OperatorV'
    t_user = 'TestE3{}'.format(random.randint(111, 9999))
    t_full_name = 'User {}'.format(user)
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
                log.info('Successfully ran : {}'.format(res['cmd']))
            else:
                log.error("Failed to import the certificate.")
                pytest.fail("Failed to import certificate.")

    user_del_out = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.CA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(user),
                                      extra_args='{} --fullName '
                                                 '"{}"'.format(t_user, 'Test {}'.format(user)))
    for result in user_del_out.values():
        if result['rc'] == 0:
            log.info('Failed to run: {}'.format(result['cmd']))
            pytest.fail('Failed to ran: {}'.format(result['cmd']))
        else:
            error = "ForbiddenException: Authorization Error"
            assert error in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
    userop.remove_user(ansible_module, user)
    userop.remove_user(ansible_module, t_user)
    ansible_module.command(group_del + group)
    ansible_module.command(client_cert_del + '"{}"'.format(user))


def test_pki_ca_user_mod_when_user_does_not_exits(ansible_module):
    """
    :Title: test pki ca-user-mod when user does not exists in database.
    :Description: Command should should not modify the user when user does not exits in database.
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults: 
        1. Verify whether pki ca-user-mod <user> should not modified the user when user is not exits in database.
    :Automated: Yes
    :CaseComponent: \-
    """

    user = "UserDoesNotExist"
    user_del_out = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.CA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                      extra_args='{} --fullName "{}"'.format(user,
                                                                             'Test {}'.format(
                                                                                 user)))
    for result in user_del_out.values():
        if result['rc'] == 0:
            log.info('Failed to run: {}'.format(result['cmd']))
            pytest.fail('Failed to ran: {}'.format(result['cmd']))
        else:
            error = "ResourceNotFoundException: No such object"
            assert error in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))


def test_pki_ca_user_mod_when_full_name_is_empty(ansible_module):
    """
    :Title: test pki ca-user-mod when fullName is empty.
    :Description: Command should should not modify the user when fullName is empty.
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults: 
        1. Verify whether pki ca-user-mod <user> should not modified the user when username is empty.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'u10'
    fullName = "Test {} {}".format(user, str(random.randint(1111, 99999)))
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    user_del_out = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.CA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                      extra_args='{} --fullName'.format(user))
    for result in user_del_out.values():
        if result['rc'] == 0:
            log.info('Failed to run: {}'.format(result['cmd']))
            pytest.fail('Failed to ran: {}'.format(result['cmd']))
        else:
            assert "MissingArgumentException: Missing argument for option: fullName" in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_mod_when_email_is_empty(ansible_module):
    """
    :Title: test pki ca-user-mod when email is empty.
    :Description: Command should should not modify the user when email is empty.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults: 
        1. Verify whether pki ca-user-mod <user> should be modified when email is empty.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'u11'
    fullName = "Test {}".format(user)
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    email = "{}@myemail.com".format(user)
    user_del_out = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.CA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                      extra_args='{} --email'.format(user))
    for result in user_del_out.values():
        if result['rc'] == 0:
            assert 'Modified user "{}"'.format(user) in result['stdout']
            assert 'User ID: {}'.format(user) in result['stdout']
            assert 'Full name: {}'.format(fullName) in result['stdout']
            assert "Email: {}".format(email) in result['stdout']
            log.info('Failed to run: {}'.format(result['cmd']))
            pytest.fail('Failed to ran: {}'.format(result['cmd']))
        else:
            assert "MissingArgumentException: Missing argument for option: email" in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_mod_when_phone_empty(ansible_module):
    """
    :Title: test pki ca-user-mod when phone is empty.
    :Description: Command should should modify the user when phone is empty.
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults: 
        1. Verify whether pki ca-user-mod <user> should be modified.
    :Automated: Yes
    :CaseComponent: \-
    """

    user = 'u12'
    fullName = "Test {}".format(user)
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    user_del_out = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.CA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                      extra_args='{} --phone'.format(user))
    for result in user_del_out.values():
        if result['rc'] == 0:
            assert 'Modified user "{}"'.format(user) in result['stdout']
            assert 'User ID: {}'.format(user) in result['stdout']
            assert 'Full name: {}'.format(fullName) in result['stdout']
            log.info('Failed to run: {}'.format(result['cmd']))
            pytest.fail('Failed to ran: {}'.format(result['cmd']))
        else:
            assert "MissingArgumentException: Missing argument for option: phone" in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_mod_when_state_empty(ansible_module):
    """
    :Title: test pki ca-user-mod when state is empty.
    :Description: Command should should not modify the user when state is empty.
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults: 
        1. Verify whether pki ca-user-mod <user> should be modified.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'u13'
    fullName = "Test {}".format(user)
    state = 'NC'
    state_mod = 'NY'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName, state=state)
    user_del_out = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.CA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                      extra_args='{} --state'.format(user))
    for result in user_del_out.values():
        if result['rc'] == 0:
            assert 'Modified user "{}"'.format(user) in result['stdout']
            assert 'User ID: {}'.format(user) in result['stdout']
            assert 'Full name: {}'.format(fullName) in result['stdout']
            log.info('Failed to run: {}'.format(result['cmd']))
            pytest.fail('Failed to ran: {}'.format(result['cmd']))
        else:
            assert "MissingArgumentException: Missing argument for option: state" in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_mod_fullname_as_old_val(ansible_module):
    """
    :Title: test pki ca-user-mod when fullName same old value.
    :Description: Command should should not modify the user when fullName old value.
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults: 
        1. Verify whether pki ca-user-mod <user> should be modified.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'u13'
    fullName = "Test {} {} ".format(user, str(random.randint(1111, 99999)))
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    user_del_out = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.CA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                      extra_args='{} --fullName "{}"'.format(user, fullName))
    for result in user_del_out.values():
        if result['rc'] == 0:
            assert 'Modified user "{}"'.format(user) in result['stdout']
            assert 'User ID: {}'.format(user) in result['stdout']
            assert 'Full name: {}'.format(fullName) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.info('Failed to run: {}'.format(result['cmd']))
            pytest.fail('Failed to ran: {}'.format(result['cmd']))
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_mod_fill_empty_values(ansible_module):
    """
    :Title: test pki ca-user-mod adding values to params which were previously empty.
    :Description: Command should should modify the user with adding values to params which were previously empty.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults:
        1. Verify whether pki ca-user-mod <user> empty should be modified.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'u13'
    fullName = "Test {} {} ".format(user, str(random.randint(1111, 99999)))
    state = 'NC'
    email = "ca_agent2@myemail.com"
    user_password = "agent2Password"
    phone = "1234567890"
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    user_del_out = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.CA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                      extra_args='{} --fullName "{}" --email "{}" --phone {} '
                                                 '--state {}'.format(user, fullName, email,
                                                                     phone, state))
    for result in user_del_out.values():
        if result['rc'] == 0:
            assert 'Modified user "{}"'.format(user) in result['stdout']
            assert 'User ID: {}'.format(user) in result['stdout']
            assert 'Full name: {}'.format(fullName) in result['stdout']
            assert "Phone: {}".format(phone) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.info('Failed to run: {}'.format(result['cmd']))
            pytest.fail('Failed to ran: {}'.format(result['cmd']))
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_mod_fullname_with_i18n(ansible_module):
    """
    :id: 13f72042-b462-4cc5-92b4-3b287efce85a
    :Title: test pki ca-user-mod when users fullName with i18 characters.
    :Description: Command should should modify the user when user fullname is contain i18n characters.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults: 
        1. Verify whether pki ca-user-mod <user> --fullName field should be modified.
    :Automated: Yes
    :CaseComponent: \-
    """
    i18nuser = "i18nuser"
    i18nuserfullname = "Örjan Äke"
    i18nuser_mod_fullname = "kakskümmend"

    cmd_out = ansible_module.pki(cli='ca-user-add',
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTPS_PORT,
                                 protocol='https',
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='"{}" --fullName "{}"'.format(i18nuser, i18nuserfullname))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added user "{}"'.format(i18nuser) in result['stdout'].encode('utf-8')
            assert 'User ID: {}'.format(i18nuser) in result['stdout'].encode('utf-8')
            assert 'Full name: {}'.format(i18nuserfullname) in result['stdout'].encode('utf-8')
            log.info('Successfully ran : {}'.format(result['cmd'].encode('utf-8')))
        else:
            assert result['rc'] >= 1
            log.info('Failed to run: {}'.format(result['cmd']))
            pytest.fail()

    user_del_out = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.CA_HTTPS_PORT,
                                      protocol="https",
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                      extra_args='"{}" --fullName "{}"'.format(i18nuser, i18nuser_mod_fullname))
    for result in user_del_out.values():
        if result['rc'] == 0:
            assert 'Modified user "{}"'.format(i18nuser) in result['stdout'].encode('utf-8')
            assert 'User ID: {}'.format(i18nuser) in result['stdout'].encode('utf-8')
            assert 'Full name: {}'.format(i18nuser_mod_fullname) in result['stdout'].encode('utf-8')
            log.info("Successfully run: {}".format(result['cmd'].encode('utf-8')))
        else:
            error = "BadRequestException: Invalid attribute syntax."
            assert error in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd'].encode('utf-8')))

    cmd_out = ansible_module.pki(cli='ca-user-del',
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTPS_PORT,
                                 protocol='https',
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='"{}"'.format(i18nuser))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Deleted user "{}"'.format(i18nuser) in result['stdout'].encode('utf-8')
            log.info('Successfully ran : {}'.format(result['cmd'].encode('utf-8')))
        else:
            assert result['rc'] >= 1
            log.info('Failed to run: {}'.format(result['cmd'].encode('utf-8')))
            pytest.fail()


def test_pki_ca_user_mod_email_with_i18n(ansible_module):
    """
    :id: c5b2d93e-3811-45b7-8292-2bd0ca002cc8
    :Title: test pki ca-user-mod when users email having i18 characters.
    :Description: Command should should modify the users email when it contain i18n characters .
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults: 
        1. Verify whether pki ca-user-mod <user> --email field should be modified.
    :Automated: Yes
    :CaseComponent: \-
    """
    i18nuser = "i18nuser"
    i18nuser_mod_fullname = "kakskümmend"
    i18nuser_mod_email = "kakskümmend@example.com"

    cmd_out = ansible_module.pki(cli='ca-user-add',
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTPS_PORT,
                                 protocol='https',
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='"{}" --fullName "{}"'.format(i18nuser, i18nuser_mod_fullname))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added user "{}"'.format(i18nuser) in result['stdout'].encode('utf-8')
            assert 'User ID: {}'.format(i18nuser) in result['stdout'].encode('utf-8')
            assert 'Full name: {}'.format(i18nuser_mod_fullname) in result['stdout'].encode('utf-8')
            log.info('Successfully ran : {}'.format(result['cmd'].encode('utf-8')))
        else:
            assert result['rc'] >= 1
            log.info('Failed to run: {}'.format(result['cmd']))
            pytest.fail()

    user_del_out = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.CA_HTTPS_PORT,
                                      protocol='https',
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                      extra_args='"{}" --email "{}"'.format(i18nuser, i18nuser_mod_email))
    for result in user_del_out.values():
        if result['rc'] == 0:
            log.info('Failed to run: {}'.format(result['cmd']))
            pytest.fail('Failed to ran: {}'.format(result['cmd']))
        else:
            error = "BadRequestException: Invalid attribute syntax."
            assert error in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd'].encode('utf-8')))
    userop.remove_user(ansible_module, i18nuser)
