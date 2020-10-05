#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI CA-USER-FIND CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki user commands needs to be tested:
#   pki ca-user-find
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

pki_cmd = "ca-user-show"
if TOPOLOGY != '01':
    CA_SUBJECT = 'CN=CA Signing Certificate,OU={},O={}'.format(constants.CA_INSTANCE_NAME,
                                                               constants.CA_SECURITY_DOMAIN_NAME)
else:
    CA_SUBJECT = 'CN=CA Signing Certificate,OU={},O={}'.format('pki-tomcat',
                                                               constants.CA_SECURITY_DOMAIN_NAME)

basic_pki_cmd = 'pki -d {} -c {} -p {} -P {} -n "{}"'.format(constants.NSSDB,
                                                       constants.CLIENT_DIR_PASSWORD,
                                                       constants.CA_HTTP_PORT, constants.PROTOCOL_UNSECURE,
                                                       constants.CA_ADMIN_NICK)

group_del = 'pki -d {} -c {} -p {} -P {} -n "{}" ' \
            'ca-group-del '.format(constants.NSSDB, constants.CLIENT_DIR_PASSWORD,
                                   constants.CA_HTTP_PORT, constants.PROTOCOL_UNSECURE, constants.CA_ADMIN_NICK)

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


@pytest.mark.parametrize('args', ['--help', '', 'asdfa'])
def test_pki_ca_user_show_help_command(ansible_module, args):
    """
    :Title: Test pki ca-user-show --help
    :Description: Command should successfully show its option for pki ca-user-show command
                usage: ca-user-show <User ID> [OPTIONS...]
                    --help   Show help options
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults:
        1. Verify whether pki ca-user-show --help command runs successfully and shows the options.
    :Automated: Yes
    :CaseComponent: \-
    """

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(args))
    for res in cmd_out.values():
        if res['rc'] == 0:
            assert "usage: ca-user-show <User ID> [OPTIONS...]" in res['stdout']
            assert re.search("--help\s+Show help message", res['stdout'])
            log.info('Successfully ran : {}'.format(res['cmd']))
        elif args == '':
            assert 'No User ID specified.' in res['stderr']
            log.info('Successfully ran : {}'.format(res['cmd']))
        elif args == 'asdfa':
            assert 'UserNotFoundException: User {} not found'.format(args) in res['stderr']
            log.info('Successfully ran : {}'.format(res['cmd']))
        else:
            log.error("Failed to run: {}".format(res['cmd']))
            pytest.fail()


@pytest.mark.parametrize("user_id", ['#', '0', '2047', '2047_symb'])
def test_pki_ca_user_show_with_diff_userid(ansible_module, user_id):
    """
    :Title: Test pki ca-user-show shows the added users
    :Description: Command should successfully show its option for pki user-add command
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. run pki ca-user-show #
        2. run pki ca-user-show 0
        3. run pki ca-user-show <2047 length>
        4. run pki ca-user-show <2047_symb>
    :ExpectedResults:
        1. It should show the users.
    :Automated: Yes
    """
    user = user_id
    if user == "2047":
        rand = subprocess.check_output(['openssl', 'rand', '-base64', '2047'])
        user = filter(str.isalnum, rand)
    fullName = 'Test %s' % user
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(user))
    for res in cmd_out.values():
        if res['rc'] == 0:
            assert 'User "{}"'.format(user) in res['stdout']
            assert 'User ID: {}'.format(user) in res['stdout']
            assert 'Full name: {}'.format(fullName) in res['stdout']
            log.info('Successfully ran : {}'.format(res['cmd']))
        else:
            log.error("Failed to run: {}".format(res['cmd']))
            pytest.fail('')
    userop.remove_user(ansible_module, user=user)


@pytest.mark.parametrize("email_id", ['#', '0', '2047', '2047_symb'])
def test_pki_ca_user_show_with_email_with_diff_chars(ansible_module, email_id):
    """
    :Title: Test pki ca-user-show with email as diff char.'#', '0' '2047', '2047_symb'
    :Description: Command should successfully add user with user id and email with different
            characters.
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults:
        1. Verify whether pki ca-user-show shows the user with user id and email with different characters.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'user2'
    fullName = 'Test %s' % user
    if email_id.startswith('2047'):
        rand = subprocess.check_output(['openssl', 'rand', '-base64', '2047'])
        email = filter(str.isalnum, rand)
        if email_id.endswith('_symb'):
            email += "!?@~#*^_+$"
    else:
        email = email_id

    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName, email=email)

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(user))
    for res in cmd_out.values():
        if res['rc'] == 0:
            assert 'User "{}"'.format(user) in res['stdout']
            assert 'User ID: {}'.format(user) in res['stdout']
            assert 'Full name: {}'.format(fullName) in res['stdout']
            assert 'Email: {}'.format(email) in res['stdout']
            log.info('Successfully ran : {}'.format(res['cmd']))
        else:
            log.error("Failed to run: {}".format(res['cmd']))
            pytest.fail('')
    userop.remove_user(ansible_module, user=user)


@pytest.mark.parametrize("state_id", ['#', '0', '2047', '2047_symb'])
def test_pki_ca_user_show_state_with_diff_chars_and_len(ansible_module, state_id):
    """
    :Title: Test pki ca-user-show with state.'#', '0' '2047', '2047_symb'
    :Description: Command should successfully add user with user id and state with different characters.
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults:
        1. Verify whether pki ca-user-show shows the user with user id and state with different characters.
    :Automated: Yes
    :CaseComponent: \-
    """

    user = 'user3'
    fullName = 'Test %s' % user
    if state_id.startswith('2047'):
        rand = subprocess.check_output(['openssl', 'rand', '-base64', '2047'])
        state = filter(str.isalnum, rand)
        if state_id.endswith('_symb'):
            state += "!?@~#*^_+$"
    else:
        state = state_id

    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName, state=state)

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(user))
    for res in cmd_out.values():
        if res['rc'] == 0:
            assert 'User "{}"'.format(user) in res['stdout']
            assert 'User ID: {}'.format(user) in res['stdout']
            assert 'Full name: {}'.format(fullName) in res['stdout']
            assert 'State: {}'.format(state) in res['stdout']
            log.info('Successfully ran : {}'.format(res['cmd']))
        else:
            log.error("Failed to run: {}".format(res['cmd']))
            pytest.fail('')
    userop.remove_user(ansible_module, user=user)


@pytest.mark.parametrize("phone_id", ['abcdefghijklmnopqrstuvwxyx12345678',
                                      '#', '0', "2047_symb", "2047", "-1234"])
def test_pki_ca_user_show_phone_with_diff_chars_and_len(ansible_module, phone_id):
    """
    :Title: pki ca-user-show with user id and phone with different characters.
    :Description: Command should successfully add user with user id and phone with diffrerent
            characters.
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults:
        1. Verify whether pki ca-user-show shows the user with user id and phone with maximum length.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'user4'
    fullName = 'Test %s' % user

    if phone_id.startswith('2047'):
        rand = subprocess.check_output(['openssl', 'rand', '-base64', '2047'])
        phone = filter(str.isalnum, rand)
        if phone_id.endswith('_symb'):
            phone += "!?@~#*^_+$"
    else:
        phone = phone_id
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName, phone=phone)

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(user))
    for res in cmd_out.values():
        if res['rc'] == 0:
            assert 'User "{}"'.format(user) in res['stdout']
            assert 'User ID: {}'.format(user) in res['stdout']
            assert 'Full name: {}'.format(fullName) in res['stdout']
            if phone_id == '-1234':
                assert 'Phone: {}'.format(phone[1:]) in res['stdout']
            else:
                assert 'Phone: {}'.format(phone) in res['stdout']
            log.info('Successfully ran: {}'.format(res['cmd']))
        else:
            assert 'UserNotFoundException: User {} not found'.format(user) in res['stderr']
            log.info('Successfully ran : {}'.format(res['cmd']))
    userop.remove_user(ansible_module, user=user)


@pytest.mark.parametrize("type_id", ['Auditors', 'Certificate Manager Agents',
                                     'Registration Manager Agents', 'Security Domain Administrators',
                                     'Subsystem Group', 'ClonedSubsystems', 'Trusted Managers'])
def test_pki_ca_user_show_with_different_user_types(ansible_module, type_id):
    """
    :Title: Test pki ca-user-show with user id and different types.
    :Description: Command should successfully add user with user id and different types such
            as Auditors, Certificate Manager Agents,Registration manager Agents,
            Security Domain Administrators, Subsystem Groups.
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults:
        1.Verify whether pki ca-user-show shows the user with user id and different types such as Auditors,
        Certificate Manager Agents,Registration manager Agents, Security Domain Administrators, Subsystem Groups.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'user4'
    fullName = 'Test %s' % user
    if type_id.startswith('2047'):
        rand = subprocess.check_output(['openssl', 'rand', '-base64', '2047'])
        u_type = filter(str.isalnum, rand)
        if type_id.endswith('_symb'):
            u_type += "!?@~#*^_+$"
    else:
        u_type = type_id
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName, type=u_type)

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(user))
    for res in cmd_out.values():
        if res['rc'] == 0:
            assert 'User "{}"'.format(user) in res['stdout']
            assert 'User ID: {}'.format(user) in res['stdout']
            assert 'Full name: {}'.format(fullName) in res['stdout']
            assert 'Type: {}'.format(u_type) in res['stdout']
            log.info('Successfully ran : {}'.format(res['cmd']))
        else:
            log.error("Failed to run: {}".format(res['cmd']))
            pytest.fail('')
    userop.remove_user(ansible_module, user=user)


def test_pki_ca_user_show_with_all_options(ansible_module):
    """
    :Title: pki ca-user-show with all options.
    :Description: Command should successfully add user with all options.
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults:
        1. Verify whether pki ca-user-show shows the user with all options.
    :Automated: Yes
    :CaseComponent: \-
    """

    user = 'user4'
    fullName = 'Test %s' % user
    email = '%s@example.com' % user
    password = 'Secret123'
    phone = '9090909090'
    state = 'NC'
    user_type = 'Administrators'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName, type=user_type,
                    email=email, password=password, phone=phone, state=state)

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(user))
    for res in cmd_out.values():
        if res['rc'] == 0:
            assert 'User "{}"'.format(user) in res['stdout']
            assert 'User ID: {}'.format(user) in res['stdout']
            assert 'Full name: {}'.format(fullName) in res['stdout']
            assert 'Phone: {}'.format(phone) in res['stdout']
            assert 'Type: {}'.format(user_type) in res['stdout']
            assert 'State: {}'.format(state) in res['stdout']
            assert 'Email: {}'.format(email) in res['stdout']
            log.info('Successfully ran : {}'.format(res['cmd']))
        else:
            log.error("Failed to run: {}".format(res['cmd']))
            pytest.fail('')
    userop.remove_user(ansible_module, user=user)


def test_pki_ca_user_show_without_user_id(ansible_module):
    """
    :Title: pki ca-user-show without user id.
    :Description: Command should successfully add user without user id.
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults: Verify whether pki ca-user-show shows the user without user id.
    :Automated: Yes
    :CaseComponent: \-
    """

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK))
    for res in cmd_out.values():
        if res['rc'] == 0:
            log.info('Failed to run: {}'.format(res['cmd']))
            pytest.fail('')
        else:
            assert "No User ID specified." in res['stderr']
            log.info('Successfully ran : {}'.format(res['cmd']))


def test_pki_ca_user_show_check_user_id_cases(ansible_module):
    """
    :Title: pki ca-user-show with case sensitive id.
    :Description: Command should successfully add user with case sensitive id.
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults: Verify whether pki ca-user-show shows the user with case sensitive id.
    :Automated: Yes
    :CaseComponent: -
    """
    user = 'user4'
    fullName = 'Test %s' % user
    email = '%s@example.com' % user
    password = 'Secret123'
    phone = '9090909090'
    state = 'NC'
    user_type = 'Administrators'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName, type=user_type,
                    email=email, password=password, phone=phone, state=state)

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(user))
    for res in cmd_out.values():
        if res['rc'] == 0:
            assert 'User "{}"'.format(user) in res['stdout']
            assert 'User ID: {}'.format(user) in res['stdout']
            assert 'Full name: {}'.format(fullName) in res['stdout']
            assert 'Phone: {}'.format(phone) in res['stdout']
            assert 'Type: {}'.format(user_type) in res['stdout']
            assert 'State: {}'.format(state) in res['stdout']
            assert 'Email: {}'.format(email) in res['stdout']
            log.info('Successfully ran : {}'.format(res['cmd']))
        else:
            log.error("Failed to run: {}".format(res['cmd']))
            pytest.fail('')
    userop.remove_user(ansible_module, user=user)


@pytest.mark.parametrize("admins", ['CA_AdminR', 'CA_AgentR'])
def test_pki_ca_user_show_using_revoked_certs(ansible_module, admins):
    """
    :Title: pki ca-user-show using revoked cert CA_AdminR and CA_AgentR
    :Description: Command should successfully add user using revoked cert CA_AdminR
                and CA_AgentR
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults: Verify whether pki ca-user-show shows the user using revoked cert CA_AdminR
            and CA_AgentR
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'user5'
    fullName = 'Test %s' % user
    state = 'NC'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName, state=state)

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(admins),
                                 extra_args='{}'.format(user))
    for res in cmd_out.values():
        if res['rc'] == 0:
            assert 'User "{}"'.format(user) in res['stdout']
            assert 'User ID: {}'.format(user) in res['stdout']
            assert 'Full name: {}'.format(fullName) in res['stdout']
            assert 'State: {}'.format(state) in res['stdout']
            log.error("Failed to run: {}".format(res['cmd']))
            pytest.fail('')
        else:
            assert "PKIException: Unauthorized" in res['stderr']
            log.info('Successfully ran : {}'.format(res['cmd']))
    userop.remove_user(ansible_module, user=user)


@pytest.mark.parametrize("admins", ['CA_AuditV', 'CA_AgentV'])
def test_pki_ca_user_show_using_valid_certs(ansible_module, admins):
    """
    :Title: pki ca-user-show using valid agent cert CA_AgentV and CA_AdminV
    :Description: Command should successfully add user using valid agent cert CA_AgentV
                and CA_AdminV.
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults: Verify whether pki ca-user-show shows the user using valid agent CA_AgentV
            and CA_AdminV.
    :Automated: Yes
    :CaseComponent: \-
    """

    user = 'user6'
    fullName = 'Test %s' % user
    state = 'NC'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName, state=state)

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(admins),
                                 extra_args='{}'.format(user))
    for res in cmd_out.values():
        if res['rc'] == 0:
            assert 'User "{}"'.format(user) in res['stdout']
            assert 'User ID: {}'.format(user) in res['stdout']
            assert 'Full name: {}'.format(fullName) in res['stdout']
            assert 'State: {}'.format(state) in res['stdout']
            log.error("Failed to run: {}".format(res['cmd']))
            pytest.fail('')
        else:
            assert "ForbiddenException: Authorization Error" in res['stderr']
            log.info('Successfully ran : {}'.format(res['cmd']))
    userop.remove_user(ansible_module, user=user)


@pytest.mark.parametrize("admins", ['CA_AdminE', 'CA_AgentE'])
def test_pki_ca_user_show_using_expired_certs(ansible_module, admins):
    """
    :Title: pki ca-user-show using valid agent cert CA_AdminE and CA_AgentE.
    :Description: Command should successfully add user using valid agent cert CA_AdminE
            and CA_AgentE.
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults: Verify whether pki ca-user-show do not shows the user using revoked agent
            CA_AdminE and CA_AgentE.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'user6'
    fullName = 'Test %s' % user
    state = 'NC'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName, state=state)

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(admins),
                                 extra_args='{}'.format(user))
    for res in cmd_out.values():
        if res['rc'] == 0:
            assert 'User "{}"'.format(user) in res['stdout']
            assert 'User ID: {}'.format(user) in res['stdout']
            assert 'Full name: {}'.format(fullName) in res['stdout']
            assert 'State: {}'.format(state) in res['stdout']
            log.error("Failed to run: {}".format(res['cmd']))
            pytest.fail('')
        else:
            assert "SEVERE: FATAL: SSL alert received: CERTIFICATE_EXPIRED\nIOException: " \
                   "SocketException cannot read on socket: Error reading from socket: " \
                   "(-12269) SSL peer rejected your certificate as expired." in res['stderr']
            log.info('Successfully ran : {}'.format(res['cmd']))
    userop.remove_user(ansible_module, user=user)


def test_pki_ca_user_show_with_ca_operatorv_cert(ansible_module):
    """
    :Title: test CA_OperatorV should not be able to show user
    :Description: Command should not show users using CA_OperatorV.
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults: Verify whether pki ca-user-show is not shows the users using CA_OperatorV.
    :Automated: Yes
    :CaseComponent: \-
    """

    user = "CA_OperatorV"
    fullName = 'CA OperatorV'
    t_user = 'TestE3%s' % random.randint(111, 9999)
    t_full_name = 'User %s' % user
    group = 'Operator'
    subject = 'UID=%s,CN=CA_OperatorV,OU=Engineering,O=Example' % (user)
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
            pytest.fail('Failed to ran: {}'.format(result['cmd']))
        else:
            error = "ForbiddenException: Authorization Error"
            assert error in result['stderr']
            log.info('Successfully ran {}.'.format(result['cmd']))
    userop.remove_user(ansible_module, user)
    userop.remove_user(ansible_module, t_user)
    ansible_module.command(group_del + group)
    ansible_module.command(client_cert_del + '"{}"'.format(user))


def test_pki_ca_user_show_with_user_cert(ansible_module):
    """
    :Title: test should not be able to show user using a user cert
    :Description: Command should successfully show its option for pki user-add command
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults: Verify whether pki ca-user-show should not able to show the users using user
            certificate.
    :Automated: Yes
    :CaseComponent: \-
    """

    user = 'user8'
    fullName = "Test %s %s " % (user, str(random.randint(1111, 99999)))
    t_user = 'tuser2%s' % str(random.randint(111, 999999))
    t_full_name = "User %s" % t_user
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    userop.add_user(ansible_module, 'add', userid=t_user, user_name=t_full_name)
    subject = 'UID=%s,CN=%s,OU=Engineering,O=Example' % (user, user)

    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 profile='caUserCert',
                                                 keysize=2048)
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
            assert 'User "{}"'.format(user) in result['stdout']
            assert 'User ID: {}'.format(user) in result['stdout']
            assert 'Full name: {}'.format(fullName) in result['stdout']
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail('Failed to ran: {}'.format(result['cmd']))
        else:
            error = "ForbiddenException: Authorization Error"
            assert error in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
    userop.remove_user(ansible_module, user)
    userop.remove_user(ansible_module, t_user)
    ansible_module.command('pki -d {} -c {} client-cert-del '
                           '{}'.format(constants.NSSDB, constants.CLIENT_DIR_PASSWORD, user))


def test_pki_ca_user_show_with_i18n_chars(ansible_module):
    """
    :id: b2792566-096f-41d3-9dc1-bb091aabdc1e
    :Title: test user show command with i18n characters
    :Description: Command should successfully add and show the users with i18n characters.
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults: Verify whether pki ca-user-show the users with i18n characters.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'user9'
    fullName = "ÖrjanÄke"
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    user_del_out = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.CA_HTTPS_PORT,
                                      protocol='https',
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                      extra_args='"{}"'.format(user))
    for result in user_del_out.values():
        if result['rc'] == 0:
            assert 'User "{}"'.format(user) in result['stdout']
            assert 'User ID: {}'.format(user) in result['stdout']
            assert 'Full name: {}'.format(fullName) in result['stdout'].encode('utf-8')
            log.info('Successfully run: {}'.format(result['cmd'].encode('utf-8')))
        else:
            log.error("Failed to run: {}".format(result['cmd'].encode('utf-8')))
            pytest.fail('Failed to ran: {}'.format(result['cmd'].encode('utf-8')))
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_show_with_i18n_chars_2(ansible_module):
    """
    :id: fca1de7a-1af9-4878-81c5-6ab204b04ac9
    :Title: test user show command with i18n characters (ÉricTêko)
    :Description: Command should successfully add and show the users with i18n characters.
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults: Verify whether pki ca-user-show the users with i18n characters.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'user10'
    fullName = "ÉricTêko"
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    user_del_out = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.CA_HTTPS_PORT,
                                      protocol='https',
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                      extra_args='"{}"'.format(user))
    for result in user_del_out.values():
        if result['rc'] == 0:
            assert 'User "{}"'.format(user) in result['stdout']
            assert 'User ID: {}'.format(user) in result['stdout']
            assert 'Full name: {}'.format(fullName) in result['stdout'].encode('utf-8')
            log.info('Successfully run: {}'.format(result['cmd'].encode('utf-8')))
        else:
            log.error("Failed to run: {}".format(result['cmd'].encode('utf-8')))
            pytest.fail('Failed to ran pki: {}'.format(result['cmd'].encode('utf-8')))
    userop.remove_user(ansible_module, user)
