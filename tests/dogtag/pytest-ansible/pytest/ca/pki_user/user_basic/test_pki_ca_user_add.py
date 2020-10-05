#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI CA-USER-ADD CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki user commands needs to be tested:
#   pki ca-user-add
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
import string
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
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
TOPOLOGY = constants.CA_INSTANCE_NAME.split("-")[1]

pki_cmd = "ca-user-add"

if TOPOLOGY != '01':
    CA_SUBJECT = 'CN=CA Signing Certificate,OU={},O={}'.format(constants.CA_INSTANCE_NAME,
                                                               constants.CA_SECURITY_DOMAIN_NAME)
else:
    CA_SUBJECT = 'CN=CA Signing Certificate,OU={},O={}'.format('pki-tomcat',
                                                               constants.CA_SECURITY_DOMAIN_NAME)

group_del = 'pki -d {} -c {} -p {} -P {} -n "{}" ' \
            'ca-group-del '.format(constants.NSSDB, constants.CLIENT_DIR_PASSWORD,
                                   constants.CA_HTTP_PORT, constants.PROTOCOL_UNSECURE, constants.CA_ADMIN_NICK)

client_cert_del = 'pki -d {} -c {} client-cert-del '.format(constants.NSSDB,
                                                            constants.CLIENT_DIR_PASSWORD)
basic_pki_cmd = 'pki -d {} -c {} -h {} -p {} -P {} -n "{}" '.format(constants.NSSDB,
                                                              constants.CLIENT_DIR_PASSWORD,
                                                              constants.MASTER_HOSTNAME,
                                                              constants.CA_HTTP_PORT,
                                                              constants.PROTOCOL_UNSECURE,
                                                              constants.CA_ADMIN_NICK)


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


@pytest.mark.parametrize('args', ['--help', '', 'sfsadf'])
def test_pki_ca_user_help_command(ansible_module, args):
    """
    :Title: test pki ca user command to show sub-commands
    :Description: Command should successfully show sub-commands for pki user command
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. pki-server ca-user --help
    :Expectedresults:
        1. Verify whether pki user command shows the following commands.
            ca-user-find        Find users
            ca-user-find        Find users
            ca-user-show        Show user
            ca-user-add         Add user
            ca-user-mod         Modify user
            ca-user-del         Remove user
            ca-user-cert        User certificate management commands
            ca-user-membership  User membership management commands
    :CaseComponent: \-
    :Automated: Yes
    """
    cmd = 'pki ca-user {}'.format(args)
    cmd_out = ansible_module.command(cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert re.search("ca-user-find\s+Find users", result['stdout'])
            assert re.search("ca-user-show\s+Show user", result['stdout'])
            assert re.search("ca-user-add\s+Add user", result['stdout'])
            assert re.search("ca-user-mod\s+Modify user", result['stdout'])
            assert re.search("ca-user-del\s+Remove user", result['stdout'])
            assert re.search("ca-user-cert\s+User certificate management commands", result['stdout'])
            assert re.search("ca-user-membership\s+User membership management commands", result['stdout'])
            log.info('Successfully run {}.'.format(cmd))
        if result['rc'] >= 1:
            assert 'Invalid module "ca-user-{}".'.format(args) in result['stderr']
            log.info('Successfully run {}.'.format(cmd))


def test_pki_ca_user_add_help_command(ansible_module):
    """
    :Title: test pki ca-user-add command to show its options
    :Description: Command should successfully show its option for pki ca-user-add command
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. pki-server ca-user-add --help
    :Expectedresults:
        1. Verify whether pki ca-user-add --help command shows the following commands.
        usage: ca-user-add <User ID> --fullName <fullname> [OPTIONS...]
            --email <email>         Email
            --fullName <fullName>   Full name
            --help                  Show help options
            --password <password>   Password
            --phone <phone>         Phone
            --state <state>         State
            --type <type>           Type
    :CaseComponent: \-
    :Automated: Yes
    """

    cmd = 'pki {} --help'.format(pki_cmd)
    cmd_out = ansible_module.command(cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "usage: {} <User ID> --fullName <fullname> [OPTIONS...]".format(pki_cmd) in result['stdout']
            assert "    --email <email>         Email" in result['stdout']
            assert "    --fullName <fullName>   Full name" in result['stdout']
            assert "    --help                  Show help message" in result['stdout']
            assert "    --password <password>   Password" in result['stdout']
            assert "    --phone <phone>         Phone" in result['stdout']
            assert "    --state <state>         State" in result['stdout']
            assert "    --type <type>           Type" in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        if result['rc'] >= 1:
            log.error('Failed to run {}'.format(cmd))
            pytest.fail('Failed to ran "pki ca-user-add --help" command')


@pytest.mark.parametrize("user_id", ["ca_agent1", "2047", "2047_symb"])
def test_pki_ca_user_add_with_different_user_id(ansible_module, user_id):
    """
    :Title: test pki ca-user-add should add user ca_agent1, user_id_with_max_length and
           user_id_with_maxlength_and_symbols command
    :Description: Command should successfully add ca_agent1, user_id_with_max_length and
                  user_id_with_maxlength_and_symbols should add to the client databse.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add user with user_id ca_agent1
        2. Add user with user_id length 2047
        3. Add user with user_id length 2047 and symb
    :Expectedresults:
        1. User ca_agent1 should get added successfully.
        2. User with user_id length 2047 should get added successfully.
        3. User with user_id length 2047 and symbols should get added successfully
    :Automated: Yes
    :CaseComponent: \-
    """
    user = ''
    if user_id == 'ca_agent1':
        user = user_id
    elif user_id.startswith('2047'):
        rand = subprocess.check_output(['openssl', 'rand', '-base64', '2047'])
        user = filter(str.isalnum, rand)
        if user_id.endswith('_symb'):
            user += "!?@~#*^_+$"
    full_name = 'User {}'.format(user_id)

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --fullName "{}"'.format(user, full_name))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added user "{}"'.format(user) in result['stdout']
            assert 'User ID: {}'.format(user) in result['stdout']
            assert 'Full name: {}'.format(full_name) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        if result['rc'] >= 1:
            log.info('Failed to run: {}'.format(result['cmd']))
            pytest.fail()
    userop.remove_user(ansible_module, user=user)


@pytest.mark.parametrize("user_id", ["abc#", "0"])
def test_pki_ca_user_add_user_id_with_different_character(user_id, ansible_module):
    """
    :Title: test pki ca-user-add should add user id as abc#, 0
    :Description: Command should successfully add user id as abc#, 0
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add user with user_id abc#
        2. Add user with user_id 0
    :Expectedresults:
        1. All the users should get added.
    :CaseComponent: \-
    :Automated: Yes
    """
    user = user_id
    full_name = 'Name {}'.format(user)

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='"{}" --fullName "{}"'.format(user, full_name))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added user "{}"'.format(user) in result['stdout']
            assert 'User ID: {}'.format(user) in result['stdout']
            assert 'Full name: {}'.format(full_name) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        if result['rc'] >= 1:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail("Failed to run: {}".format(result['cmd']))
    userop.remove_user(ansible_module, user=user)


@pytest.mark.parametrize("email_id", ["#", "0", "2047", "2047_symb"])
def test_pki_ca_user_add_with_maximum_email_length(ansible_module, email_id):
    """
    :Title: test pki ca-user-add should add user with and maximum email length and chars
    :Description: Command should successfully add user with maximum email length.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. pki ca-user-add testuser --fullName "User #" --email '#'
        2. pki ca-user-add testuser --fullName "User 0" --email '0'
        3. pki ca-user-add testuser --fullName "User 2047" --email '2047'
        4. pki ca-user-add testuser --fullName "User 2047 + Symb" --email '2047 + Symb'
    :Expectedresults:
        1. Verify all the users should get added.
    :CaseComponent: \-
    :Automated: Yes
    """
    user = 'u1_' + "".join([random.choice(string.ascii_letters)
                            for _ in range(5)]) + str(random.randint(1, 999999))
    email = ''
    if not email_id.startswith('2047'):
        email = email_id
    elif email_id.startswith('2047'):
        rand = subprocess.check_output(['openssl', 'rand', '-base64', '2047'])
        email = filter(str.isalnum, rand)
        if email_id.endswith('_symb'):
            email += "!?@~#*^_+$"
    full_name = "User " + email_id

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --fullName "{}" --email {}'.format(user, full_name,
                                                                                   email))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added user "{}"'.format(user) in result['stdout']
            assert 'User ID: {}'.format(user) in result['stdout']
            assert 'Full name: {}'.format(full_name) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        if result['rc'] >= 1:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail('Failed to ran pki: {}'.format(result['cmd']))

    userop.remove_user(ansible_module, user=user)


@pytest.mark.parametrize("user_state", ["#", "0", "2047", "2047_symb"])
def test_pki_ca_user_add_with_different_state_char(user_state, ansible_module):
    """
    :Title: test pki ca-user-add should add user with different state characters
    :Description: Command should successfully add user with different state characters.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. pki ca-user-add testuser --state #
        2. pki ca-user-add testuser --state 0
        3. pki ca-user-add testuser --state 2047
        4. pki ca-user-add testuser --state 2047_symb
    :Expectedresults: 
        1. All the users should get added with different char which passed to --state.
    :CaseComponent: \-
    :Automated: Yes
    """
    user = 'u2_' + "".join([random.choice(string.ascii_letters)
                            for _ in range(5)]) + str(random.randint(111, 999999))
    state = ''
    if not user_state.startswith('2047'):
        state = user_state
    elif user_state.startswith('2047'):
        rand = subprocess.check_output(['openssl', 'rand', '-base64', '2047'])
        state = filter(str.isalnum, rand)
        if user_state.endswith('_symb'):
            state += "!?@~#*^_+$"

    full_name = "User " + user

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --fullName "{}" --state {}'.format(user, full_name,
                                                                                   state))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added user "{}"'.format(user) in result['stdout']
            assert 'User ID: {}'.format(user) in result['stdout']
            assert 'Full name: {}'.format(full_name) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))

        if result['rc'] >= 1:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail('Failed to run: {}'.format(result['cmd']))
    userop.remove_user(ansible_module, user=user)


@pytest.mark.parametrize("phone_char", ["#", "?", "-1234",
                                        "2047", "2047_symb"])
def test_pki_ca_user_add_phone_with_different_chars(phone_char, ansible_module):
    """
    :Title: test pki ca-user-add should add user with different phone characters
    :Description: Command should successfully add user with different characters passed to phone.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. pki ca-user-add testuser --fullName testuser1 --phone #
        2. pki ca-user-add testuser --fullName testuser1 --phone ?
        3. pki ca-user-add testuser --fullName testuser1 --phone -1232
        4. pki ca-user-add testuser --fullName testuser1 --phone 2047 length
        5. pki ca-user-add testuser --fullName testuser1 --phone 2047 length + symbols
    :Expectedresults: 
        1. Steps 1 to 3 should be successfully add the user with phone.
        2. Steps 4 and 5 should failed to add the user.
    :CaseComponent: \-
    :Automated: Yes
    """

    user = 'u3_' + "".join([random.choice(string.ascii_letters)
                            for _ in range(5)]) + str(random.randint(111, 999999))
    phone = ''
    if not phone_char.startswith('2047'):
        phone = phone_char
    elif phone_char.startswith('2047'):
        rand = subprocess.check_output(['openssl', 'rand', '-base64', '2047'])
        phone = filter(str.isalnum, rand)
        if phone_char.endswith('_symb'):
            phone += "!?@~#*^_+$"
    full_name = "User " + user

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --fullName "{}" --phone {} '.format(user, full_name,
                                                                                    phone))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added user "{}"'.format(user) in result['stdout']
            assert 'User ID: {}'.format(user) in result['stdout']
            assert 'Full name: {}'.format(full_name) in result['stdout']
            log.info("Failed to run run: {}".format(result['cmd']))

        if result['rc'] >= 1:
            assert "BadRequestException: Invalid attribute syntax" in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
    userop.remove_user(ansible_module, user=user)


@pytest.mark.parametrize("user_type", ["Auditors", "Certificate Manager Agents",
                                       'Registration Manager Agents', 'Subsytem Group',
                                       'Security Domain Administrators', 'ClonedSubsystems',
                                       'Trusted Managers', 'Dummy Group'])
def test_pki_ca_user_add_to_different_type_groups(user_type, ansible_module):
    """
    :Title: test add user with with different user types.
    :Description: Command should successfully add user with type as Auditors
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. pki ca-user-add testuser --fullName testuser --type Auditors
        2. pki ca-user-add testuser --fullName testuser --type 'Certificate Manager Agents'
        3. pki ca-user-add testuser --fullName testuser --type 'Registration Manager Agents'
        4. pki ca-user-add testuser --fullName testuser --type 'Subsystem Group'
        5. pki ca-user-add testuser --fullName testuser --type 'Security Domain Administrators'
        6. pki ca-user-add testuser --fullName testuser --type 'ClonedSubsystems'
        7. pki ca-user-add testuser --fullName testuser --type 'Trusted Managers'
        8. pki ca-user-add testuser --fullName testuser --type 'Dummy Group'
    :Expectedresults:
        1. Command should add all the users in different user types.
    :CaseComponent: \-
    :Automated: Yes
    """
    user = 'u4_' + "".join([random.choice(string.ascii_letters)
                            for _ in range(5)]) + str(random.randint(111, 99999))
    full_name = "User " + user
    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --fullName "{}" --type "{}"'.format(user, full_name,
                                                                                    user_type))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added user "{}"'.format(user) in result['stdout']
            assert 'User ID: {}'.format(user) in result['stdout']
            assert 'Full name: {}'.format(full_name) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))

        if result['rc'] >= 1:
            assert "BadRequestException: Invalid attribute syntax." in result['stderr']
            log.warning("Failed to run: {}".format(result['cmd']))
            pytest.fail()
    userop.remove_user(ansible_module, user=user)


def test_pki_ca_user_add_without_fullName(ansible_module):
    """
    :Title: test pki ca-user-add should add user without fullName and and user ID "ca_agent2"
    :Description: Command should not add user without fullName to the database.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. pki ca-user-add testuser1
    :Expectedresults:
        1. It should not add the user to the database.
    :CaseComponent: \-
    :Automated: Yes
    """
    user = 'ca_agent2'
    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(user))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added user "{}"'.format(user) in result['stdout']
            assert 'User ID: {}'.format(user) in result['stdout']
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()
        if result['rc'] >= 1:
            assert "ERROR: Missing full name" in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))


def test_pki_ca_user_add_with_all_options(ansible_module):
    """
    :Title: test pki ca-user-add should add user with all options are provided
    :Description: Command successfully add user with all options to the database.
            user ID "u5"
            email "u5@myemail.com"
            password "agent2password"
            phone "1234567890"
            state "NC"
            type Administrators
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. pki ca-user-add u5 --fullName "TestUser 5" --email u5@example.com
            --password agent2password --phone 1234567890 --state NC --type Administrators
    :Expectedresults:
        1. User should get added to the database with all the options.
    :CaseComponent: \-
    :Automated: Yes
    """
    full_name = 'Test ca_agent'
    email = 'u5@myemail.com'
    password = 'agent2Password'
    phone = '1234567890'
    state = 'NC'
    type = 'Administrators'
    user = 'u5'

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --fullName "{}" --email {} --password {} '
                                            '--phone {} --state {} '
                                            '--type {}'.format(user, full_name, email, password,
                                                               phone, state, type))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added user "{}"'.format(user) in result['stdout']
            assert 'User ID: {}'.format(user) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))

        if result['rc'] >= 1:
            log.error("Successfully run: {}".format(result['cmd']))
            pytest.fail("Failed to run: {}".format(result['cmd']))
    userop.remove_user(ansible_module, user=user)


def test_pki_ca_user_add_to_multiple_groups(ansible_module):
    """
    :Title: pki ca-user-add, add user with all options and add user to multiple group
    :Description: test pki ca-user-add should add user with all options and add user to multiple group
             and user ID "u6"
             email "multiplegroup@myemail.com"
             password "agent2password"
             phone "1234567890"
             state "NC"
             State NC
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. pki ca-user-add u6 --fullName "TestUser 6" --email u6@example.com
            --password agent2password --phone 1234567890 --state NC --type Administrators
        2. pki ca-user-membership-add u6 "Certificate Manager Agents"
    :Expectedresults:
        1. It should add the user.
        2. It should add the user to "Certificate Manager Agents" group.
    :CaseComponent: \-
    :Automated: Yes
    """

    full_name = 'Multiple Group User'
    email = 'multiplegroup@myemail.com'
    password = 'agent2Password'
    phone = '1234567890'
    state = 'NC'
    type = 'Administrators'
    user = 'u6'
    groups = ['Administrators', 'Certificate Manager Agents']

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --fullName "{}" --email {} --password {} --phone '
                                            '{} --state {} --type {}'.format(user, full_name, email,
                                                                             password, phone,
                                                                             state, type))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added user "{}"'.format(user) in result['stdout']
            assert 'User ID: {}'.format(user) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))

            for group in groups:
                add_users = ansible_module.pki(cli='ca-user-membership-add',
                                               nssdb=constants.NSSDB,
                                               dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                               port=constants.CA_HTTP_PORT,
                                               hostname=constants.MASTER_HOSTNAME,
                                               certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                               extra_args='{} "{}"'.format(user, group))

                for res in add_users.values():
                    if res['rc'] == 0:
                        assert 'Added membership in "{}"'.format(group) in res['stdout']
                        assert 'Group: {}'.format(group) in res['stdout']
                        log.info('Successfully ran : {}'.format(res['cmd']))
                    else:
                        log.error("Failed to run: {}".format(res['cmd']))
                        pytest.fail("Failed.")
        if result['rc'] >= 1:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail("Failed to run: {}".format(result['cmd']))
    userop.remove_user(ansible_module, user=user)


def test_pki_ca_user_add_with_short_passwd(ansible_module):
    """
    :Title: pki ca-user-add, add user with all options and add user with short password
    :Description: test pki ca-user-add should add user with all options and add user with short
    password and user ID "u7" password "pass"
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. pki ca-user-add testU2 --fullName testuser2 --pass pass
    :Expectedresults:
        1. It should not add the user with short password.
    :CaseComponent: \-
    :Automated: Yes
    """
    user = 'u7'
    full_name = 'User {}'.format(user)
    password = 'pass'
    user_add = ansible_module.pki(cli=pki_cmd,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  port=constants.CA_HTTP_PORT,
                                  hostname=constants.MASTER_HOSTNAME,
                                  certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                  extra_args='{} --fullName "{}" '
                                             '--password {}'.format(user, full_name, password))

    for result in user_add.values():
        if result['rc'] == 0:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()

        if result['rc'] >= 1:
            assert "PKIException: The password must be at least 8 characters" in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))


@pytest.mark.parametrize('users', ['CA_AgentR', 'CA_AdminR'])
def test_pki_ca_user_add_using_revoked_certs(users, ansible_module):
    """
    :Title: pki ca-user-add, add user with revoked admin, agent certificate.
    :Description: test pki ca-user-add should not add the user with revoked admin certificate.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. pki -n CA_AgentR ca-user-add TestU3 --fullName "User TestU3"
        2. pki -n CA_AdminR ca-user-add TestU3 --fullName "User TestU3"
    :Expectedresults:
        1. Adding user should fail.
    :CaseComponent: \-
    :Automated: Yes
    """

    user = 'u8_{}'.format(random.randint(111, 9999))
    full_name = 'User {}'.format(user)

    user_add = ansible_module.pki(cli=pki_cmd,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  port=constants.CA_HTTP_PORT,
                                  hostname=constants.MASTER_HOSTNAME,
                                  certnick='"{}"'.format(users),
                                  extra_args='{} --fullName "{}"'.format(user, full_name))

    for result in user_add.values():
        if result['rc'] == 0:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()

        if result['rc'] >= 1:
            log.info('Successfully ran : {}'.format(result['cmd']))
            assert "PKIException: Unauthorized" in result['stderr']


@pytest.mark.parametrize('users', ['CA_AgentV', 'CA_AuditV'])
def test_pki_ca_user_add_with_valid_certs(users, ansible_module):
    """
    :Title: pki ca-user-add, add user with valid agent user certificate.
    :Description: test pki ca-user-add should not add the user with valid agent certificate.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. pki -n CA_AgentV ca-user-add --fullName "User U9" u9
        2. pki -n CA_AuditV ca-user-add --fullName "User U9" u9
    :Expectedresults:
        1. All the users should get added successfully.
    :CaseComponent: \-
    :Automated: Yes
    """
    user = 'u9_{}'.format(random.randint(111, 9999))
    full_name = 'User {}'.format(user)
    user_add = ansible_module.pki(cli=pki_cmd,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  port=constants.CA_HTTP_PORT,
                                  hostname=constants.MASTER_HOSTNAME,
                                  certnick='"{}"'.format(users),
                                  extra_args='{} --fullName "{}" '.format(user, full_name))

    for result in user_add.values():
        if result['rc'] == 0:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()

        if result['rc'] >= 1:
            assert "ForbiddenException: Authorization Error" in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))


@pytest.mark.parametrize('users', ['CA_AdminE', 'CA_AgentE'])
def test_pki_ca_user_add_using_expired_user_certs(users, ansible_module):
    """
    :Title: pki ca-user-add, add user with expired admin, agent certificate.
    :Description: test pki ca-user-add should not add the user with expired admin certificate.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. pki -n CA_AdminE ca-user-add u10 --fullName 'User u10'
        2. pki -n CA_AgentE ca-user-add u10 --fullName 'User u10'
    :Expectedresults:
        1. With expired admin and agent cert user should not get added to the database.
    :CaseComponent: \-
    :Automated: Yes
    """

    user = 'u10_{}'.format(random.randint(111, 9999))
    full_name = 'User {}'.format(user)
    user_add = ansible_module.pki(cli=pki_cmd,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  port=constants.CA_HTTP_PORT,
                                  hostname=constants.MASTER_HOSTNAME,
                                  certnick='"{}"'.format(users),
                                  extra_args='{} --fullName "{}"'.format(user, full_name))

    for result in user_add.values():
        if result['rc'] == 0:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()

        if result['rc'] >= 1:
            assert "SEVERE: FATAL: SSL alert received: CERTIFICATE_EXPIRED\nIOException: " \
                   "SocketException cannot read on socket: Error reading from socket: " \
                   "(-12269) SSL peer rejected your certificate as expired." in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))


def test_pki_ca_user_add_using_operator_user(ansible_module):
    """
    :Title: pki ca-user-add, command should not add user when ca user is in operator group.
    :Description: test pki ca-user-add. User who is in Operator group does not add the users.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add Operator user add Operator group.
        2. Create certificate for operator user assign certificate to the user.
        3. Import certificate to the client database
        4. Try to add the user using using operator user.
    :Expectedresults:
        1. It should not able to add the user.
    :CaseComponent: \-
    :Automated: Yes
    """
    user = 'CA_OperatorV'
    full_name = 'CA OperatorV'
    group = 'Operator'
    subject = 'UID={},CN={}'.format(user, full_name)
    userop.add_user(ansible_module, 'add', userid=user, user_name=full_name)
    group_add = basic_pki_cmd + ' ca-group-add {} --description "Operator Group"'.format(group)
    user_add_to_group = basic_pki_cmd + " ca-user-membership-add {} {}".format(user, group)
    ansible_module.command(group_add)
    ansible_module.command(user_add_to_group)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 profile='caUserCert',
                                                 keysize=2048)
    log.info("Generating certificate with subject : {}".format(subject))
    log.info("Generated certificate : {}".format(cert_id))
    cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
    add_cert_to_user(ansible_module, user, subject, cert_id, cert_subject)
    import_cert = basic_pki_cmd + ' client-cert-import {} --serial {}'.format(user, cert_id)
    import_out = ansible_module.command(import_cert)
    for result in import_out.values():
        if result['rc'] == 0:
            assert 'Imported certificate "{}"'.format(user) in result['stdout']
            log.info("Imported certificate for user '{}'".format(user))
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error("Failed to import certificate.")
            pytest.fail("")

    user_add2 = ansible_module.pki(cli=pki_cmd,
                                   nssdb=constants.NSSDB,
                                   dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                   port=constants.CA_HTTP_PORT,
                                   hostname=constants.MASTER_HOSTNAME,
                                   certnick='"{}"'.format(user),
                                   extra_args='--fullName "User 10" u10')

    for res in user_add2.values():
        if res['rc'] == 0:
            log.error("Failed to run: {}".format(res['cmd']))
            pytest.fail()

        if res['rc'] >= 1:
            error = "ForbiddenException: Authorization Error"
            assert error in res['stderr']
            log.info('Successfully ran : {}'.format(res['cmd']))
    userop.remove_user(ansible_module, user=user)
    ansible_module.command(group_del + group)
    ansible_module.command(client_cert_del + '"{}"'.format(user))


def test_pki_ca_user_add_when_user_id_limit_exceed(ansible_module):
    """
    :Title: pki ca-user-add, user id exceeds maximum limit definded in schema.
    :Description: test pki ca-user-add, user id exceeds maximum limit defined in schema.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add user with maximum length.
    :Expectedresults:
        1. User should get added with maximum length.
    :Automated: Yes
    :CaseComponent: \-
    """

    openssl_cmd = ['openssl', 'rand', '-base64', '80000']
    raw_str = subprocess.check_output(openssl_cmd)
    openssl_key = filter(str.isalpha, raw_str)
    user_add2 = ansible_module.pki(cli=pki_cmd,
                                   nssdb=constants.NSSDB,
                                   dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                   port=constants.CA_HTTP_PORT,
                                   hostname=constants.MASTER_HOSTNAME,
                                   certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                   extra_args='--fullName "User 11" {}'.format(openssl_key))
    for result in user_add2.values():
        if result['rc'] == 0:
            log.debug("Failed to run: {}".format(result['cmd']))
            userop.remove_user(ansible_module, user=openssl_key)
            pytest.fail()
        elif result['rc'] >= 1:
            try:
                assert "PKIException: Internal Server Error" in result['stderr']
            except Exception as e:
                assert "PKIException: Bad Request" in result['stderr']
                print(e)
            log.info('Successfully ran : {}'.format(result['cmd']))


def test_pki_ca_user_add_using_normal_user_cert(ansible_module):
    """
    :Title: pki ca-user-add, add user using user cert.
    :Description: test pki ca-user-add, add user using user cert
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add User, add cert to user.
        2. Add new user using recently created user.
    :Expectedresults:
        1. Adding user should fail.
    :CaseComponent: \-
    :Automated: Yes
    """

    user = "u13"
    full_name = 'User {}'.format(user)
    subject = 'UID={},CN={}'.format(user, full_name)
    userop.add_user(ansible_module, 'add', userid=user, user_name=full_name)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 profile='caUserCert',
                                                 keysize=2048)
    if cert_id:
        log.info("Issued certificate for user {} : {}".format(user, cert_id))
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
        add_cert_to_user(ansible_module, user, subject, cert_id, cert_subject)
        import_cert = basic_pki_cmd + ' client-cert-import {} --serial {}'.format(user, cert_id)
        import_out = ansible_module.command(import_cert)
        for result in import_out.values():
            if result['rc'] == 0:
                assert 'Imported certificate "{}"'.format(user) in result['stdout']
                log.info("Imported certificate for user '{}'".format(user))
                log.info('Successfully ran : {}'.format(result['cmd']))
            else:
                log.error("Failed to import certificate.")
                pytest.fail("")

        t_user = 'testuser101'
        t_fullname = 'Test user101'
        add_user = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.CA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(user),
                                      extra_args='{} --fullName "{}"'.format(t_user,
                                                                             t_fullname))
        for result in add_user.values():
            if result['rc'] == 0:
                assert 'Added user "{}"'.format(t_user) in result['stdout']
                assert 'User ID: {}'.format(t_user) in result['stdout']
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail("")
            else:
                assert "ForbiddenException: Authorization Error" in result['stderr']
                log.info('Successfully ran : {}'.format(result['cmd']))

    userop.remove_user(ansible_module, user=user)
    ansible_module.command(client_cert_del + '"{}"'.format(user))


def test_pki_ca_user_add_using_invalid_cred(ansible_module):
    """
    :Title: pki ca-user-add, add ca user using invalid user credential.
    :Description: test pki ca-user-add, add ca user using invalid user credential.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. pki -n "NonExistedCert" ca-user-add --fullName "Test User1" testuser1
    :Expectedresults:
        1. Adding user should fail.
    :CaseComponent: \-
    :Automated: Yes
    """
    user = 'u14'
    fullName = 'Test {}'.format(user)
    user_add2 = ansible_module.pki(cli=pki_cmd,
                                   nssdb=constants.NSSDB,
                                   dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                   port=constants.CA_HTTP_PORT,
                                   hostname=constants.MASTER_HOSTNAME,
                                   certnick='"{}"'.format('NonExistedCert'),
                                   extra_args='--fullName "{}" {}'.format(fullName, user))
    for result in user_add2.values():
        if result['rc'] == 0:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail("Failed to run: {}".format(result['cmd']))
        elif result['rc'] >= 0:
            assert 'RuntimeException: org.mozilla.jss.crypto.ObjectNotFoundException: ' \
                   'Certificate not found: NonExistedCert' in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
