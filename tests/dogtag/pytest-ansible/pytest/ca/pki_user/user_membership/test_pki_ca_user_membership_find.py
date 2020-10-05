#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI CA-USER-MEMBERSHIP-FIND CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki user commands needs to be tested:
#   pki ca-user-membership-find
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

pki_cmd = "ca-user-membership-find"
if TOPOLOGY != '01':
    CA_SUBJECT = 'CN=CA Signing Certificate,OU={},O={}'.format(constants.CA_INSTANCE_NAME,
                                                               constants.CA_SECURITY_DOMAIN_NAME)
else:
    CA_SUBJECT = 'CN=CA Signing Certificate,OU={},O={}'.format('pki-tomcat',
                                                               constants.CA_SECURITY_DOMAIN_NAME)

basic_pki_cmd = 'pki -d {} -c {} -h {} -p {} -P {} -n "{}" '.format(constants.NSSDB,
                                                              constants.CLIENT_DIR_PASSWORD,
                                                              constants.MASTER_HOSTNAME,
                                                              constants.CA_HTTP_PORT,
                                                              constants.PROTOCOL_UNSECURE,
                                                              constants.CA_ADMIN_NICK)

group_del = 'pki -d {} -c {} -h {} -p {} -P {} -n "{}" ' \
            'ca-group-del '.format(constants.NSSDB, constants.CLIENT_DIR_PASSWORD,
                                   constants.MASTER_HOSTNAME, constants.CA_HTTP_PORT,
                                   constants.PROTOCOL_UNSECURE, constants.CA_ADMIN_NICK)

client_cert_del = 'pki -d {} -c {} client-cert-del '.format(constants.NSSDB,
                                                            constants.CLIENT_DIR_PASSWORD)

groups = ["Certificate Manager Agents", "Registration Manager Agents",
          "Subsystem Group", "Trusted Managers", "Administrators", "Auditors",
          "ClonedSubsystems", "Security Domain Administrators"]


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


def test_pki_ca_user_membership_find_with_help_option(ansible_module):
    """
    :Title: Test pki ca-user-membership-find, command should show the help option.
    :Description: Command should show the pki ca-user-membership-find --help command options.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults:
        1. Verify whether pki ca-user-membership-find, should show the expected options.
    :Automated: Yes 
    :CaseComponent: \-
    """
    cmd = 'pki {} --help'.format(pki_cmd)
    cmd_out = ansible_module.command(cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'usage: ca-user-membership-find <User ID> [FILTER] [OPTIONS...]' in result['stdout']
            assert re.search('--help\s+Show help message.', result['stdout'])
            assert '--size <size>     Page size' in result['stdout']
            assert '--start <start>   Page start' in result['stdout']
            log.info("Successfully run: {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run: {}".format(" ".join(result['cmd'])))
            pytest.fail()


@pytest.mark.parametrize('args', ['', 'asdfa'])
def test_pki_ca_user_membership_find_with_invalid_args(ansible_module, args):
    """
    :Title: Test pki ca-user-membership with invalid args, like '' and asdfa
    :Description: Test pki ca-user-membership-find with invalid args, like '' and asdfa
    :Requirement: Certificate Authority Users
    :Steps:
        1. Run pki ca-user-membership-find ''
        2. Run pki ca-user-membership-find asdfa
    :ExpectedResults:
        1. It should throw an exception.
        2. It should throw an exception.
    :Automated: Yes
    :CaseComponent: \-
    """
    cmd_out = ansible_module.pki(cli='ca-user-membership-find',
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(args))
    for result in cmd_out.values():
        if result['rc'] == 0:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()
        if result['rc'] >= 1:
            if args == 'asdfa':
                assert 'UserNotFoundException: User asdfa not found' in result['stderr']
                log.info("Successfully run: {}".format(result['cmd']))
            if args == '':
                assert 'Incorrect number of arguments specified.' in result['stderr']
                log.info("Successfully run: {}".format(result['cmd']))


def test_pki_ca_user_membership_find_when_user_is_in_different_group(ansible_module):
    """
    :Title: Test pki ca-user-membership-find, command shoud show the user membership when it is added in differnt groups.
    :Description: Command should show the user membership when it is added in different groups.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add user.
        2. Add user to the Administrators
        3. Add user to the "Certificate Manager Agents"
        4. Add user to the "Registration Manager Agents"
        5. Add user to the "Subsystem Group"
        6. Add user to the "Trusted Managers"
        7. Add user to the Auditors
        8. Run pki ca-user-membership-find <user>
    :ExpectedResults:
        1. Command should show user membership when it is added in different groups.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'testuser01'
    fullName = 'Test User01'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    for i in groups:
        cmd_out = ansible_module.pki(cli='ca-user-membership-add',
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='{} "{}"'.format(user, i))

        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Added membership in "{}"'.format(i) in result['stdout']
                assert 'Group: {}'.format(i) in result['stdout']
                log.info("Successfully run: {}".format(result['cmd']))
            else:
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()
    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(user))

    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "{} entries matched".format(len(groups)) in result['stdout']
            for j in groups:
                assert 'Group: {}'.format(j) in result['stdout']
                log.info("Found membership in: {}".format(j))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()
    userop.remove_user(ansible_module, user)


@pytest.mark.parametrize('start', ['0', '-1', '5', '15', 'abc'])
def test_pki_ca_user_membership_find_with_diff_start_size(ansible_module, start):
    """
    :Title: Test cli with different start sizes, 0, -1, 5, 15, abc.
    :Description: Test cli with different sizes, 0, -1, 5, 15, abc.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-user-membership-find --start 0
        2. Run pki ca-user-membership-find --start -1
        3. Run pki ca-user-membership-find --start 5
        4. Run pki ca-user-membership-find --start 15
        5. Run pki ca-user-membership-find --start abc
    :ExpectedResults: 
        1. It should show all group list form start.
        2. It should not show any group list.
        3. It should show group list start from 5.
        4. It should show group list from 15 if exists otherwise 0 entries
        5. It should throw an error.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'testuser02'
    fullName = 'Test User02'

    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    for i in groups:
        cmd_out = ansible_module.pki(cli='ca-user-membership-add',
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='{} "{}"'.format(user, i))

        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Added membership in "{}"'.format(i) in result['stdout']
                assert 'Group: {}'.format(i) in result['stdout']
                log.info("Successfully run: {}".format(result['cmd']))
            else:
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --start {}'.format(user, start))

    for result in cmd_out.values():
        if result['rc'] == 0:
            e_start = 0 if int(start) <= 0 else int(start)
            if e_start <= 0:
                assert '{} entries matched'.format(len(groups)) in result['stdout']
            else:
                if e_start > len(groups):
                    assert "Number of entries returned 0" in result['stdout']
                else:
                    assert '{} entries matched'.format(len(groups)) in result['stdout']
                    for i in groups[e_start:]:
                        assert 'Group: {}'.format(i) in result['stdout']
                    entries = 0 if (len(groups) - e_start) < 0 else len(groups) - e_start
                    assert "Number of entries returned {}".format(entries) in result['stdout']
                log.info("Successfully run: {}".format(result['cmd']))
        elif result['rc'] >= 1:
            assert 'NumberFormatException: For input string: "abc"' in result['stderr']
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()
    userop.remove_user(ansible_module, user)


@pytest.mark.parametrize('size', ['-1', '0', '5', '15', '100', 'abc'])
def test_pki_ca_user_membership_find_with_diff_size(ansible_module, size):
    """
    :Title: Test pki ca-user-membership-find, find membership of a user when page size is zero (0).
    :Description: Command should show the membership of the user when page size is zero(0).
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add user, Add user to differnt groups.
        2. Run pki ca-user-membership-find --size -1
        3. Run pki ca-user-membership-find --size 0
        4. Run pki ca-user-membership-find --size 5
        5. Run pki ca-user-membership-find --size 15
        6. Run pki ca-user-membership-find --size 100
        7. Run pki ca-user-membership-find --size abc
    :ExpectedResults:
        1. It should return 0 entries.
        2. It should return 0 entries
        3. It should return 5 entries.
        4. It should return entries till 15
        5. It should return entries till 100
        6. It should throw an Exception.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'testuser03'
    fullName = 'Test User03'

    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    for i in groups:
        cmd_out = ansible_module.pki(cli='ca-user-membership-add',
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='{} "{}"'.format(user, i))

        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Added membership in "{}"'.format(i) in result['stdout']
                assert 'Group: {}'.format(i) in result['stdout']
                log.info("Successfully run: {}".format(result['cmd']))
            else:
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --size {}'.format(user, size))

    for result in cmd_out.values():
        if result['rc'] == 0:
            e_size = 0 if int(size) <= 0 else int(size)
            if e_size <= 0:
                assert '{} entries matched'.format(len(groups)) in result['stdout']
            else:
                assert '{} entries matched'.format(len(groups)) in result['stdout']
                if e_size > len(groups):
                    assert "Number of entries returned {}".format(len(groups)) in result['stdout']

                else:
                    for i in groups[:e_size]:
                        assert 'Group: {}'.format(i) in result['stdout']
                log.info("Successfully run: {}".format(result['cmd']))
        elif result['rc'] >= 1:
            assert 'NumberFormatException: For input string: "abc"' in result['stderr']
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()
    userop.remove_user(ansible_module, user)


@pytest.mark.parametrize('start,size', [('6', '5'), ('6', '5638922588'), ('5638922588', '5')])
def test_pki_ca_user_membership_find_with_start_and_size_option(ansible_module, start, size):
    """
    :Title: Test find membership of a user with page start and page size option.
    :Description: Command should show the groups of user with page start and page size option.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add user. Add users to the groups.
        2. Run pki ca-user-membership-find --start 6 --size 5
        3. Run pki ca-user-membership-find --start 6 --size 5638922588
        4. Run pki ca-user-membership-find --start 5638922588 --size 5
    :ExpectedResults:
        1. Command should show the user with page start and page size option.
        2. Command should show all the entries associated with user.
        3. Command should throw an Exception
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'testuser04'
    fullName = 'Test User04'

    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    for i in groups:
        cmd_out = ansible_module.pki(cli='ca-user-membership-add',
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='{} "{}"'.format(user, i))

        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Added membership in "{}"'.format(i) in result['stdout']
                assert 'Group: {}'.format(i) in result['stdout']
                log.info("Successfully run: {}".format(result['cmd']))
            else:
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()
    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --start {} --size {}'.format(user, start, size))

    for result in cmd_out.values():
        if result['rc'] == 0:
            e_start = 0 if int(start) <= 0 else int(start)
            returned_entries = len(groups) - e_start
            assert '{} entries matched'.format(len(groups)) in result['stdout']
            if e_start <= 0 or returned_entries > len(groups):
                assert "Number of entries returned 0" in result['stdout']
            else:
                if e_start > len(groups):
                    assert "Number of entries returned 0" in result['stdout']
                else:
                    for i in groups[e_start:]:
                        assert 'Group: {}'.format(i) in result['stdout']
                    assert "Number of entries returned {}".format(returned_entries) in result['stdout']
                log.info("Successfully run: {}".format(result['cmd']))
        elif result['rc'] >= 1:
            string = None
            if len(start) > 2:
                string = start
            elif len(size) > 2:
                string = size
            assert 'NumberFormatException: For input string: "{}"'.format(string) in result['stderr']
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()
    userop.remove_user(ansible_module, user)


@pytest.mark.parametrize("admins", ['CA_AdminR', 'CA_AgentR', 'CA_AuditR'])
def test_pki_ca_user_membership_find_with_revoked_certs(ansible_module, admins):
    """
    :Title: Test find membership of a user with CA_AdminR, CA_AgentR and CA_AuditR
    :Description: Command should not show membership of user with CA_AdminR.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Run pki -n CA_AdminR ca-user-membership-find <user>
        2. Run pki -n CA_AgentR ca-user-membership-find <user>
        3. Run pki -n CA_AuditR ca-user-membership-find <user>
    :ExpectedResults:
        1. Command should fail with CA_AdminR.
        2. Command should fail with CA_AgentR.
        3. Command should fail with CA_AuditR.
    :Automated: Yes
    :CaseComponent: \-
    """

    user = constants.CA_ADMIN_USERNAME
    group = 'Administrators'

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(admins),
                                 extra_args='{} "{}"'.format(user, group))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Group: ' in result['stdout']
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()
        else:
            error = "PKIException: Unauthorized"
            assert error in result['stderr']
            log.info("Successfully run: {}".format(result['cmd']))


@pytest.mark.parametrize("admins", ['CA_AgentV', 'CA_AuditV'])
def test_pki_ca_user_membership_find_with_valid_admins(ansible_module, admins):
    """
    :Title: Test pki ca-user-membership-find, find membership of a user with CA_AgentV,
    :Description: Command should not show user membership with CA_AgentV.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Run pki -n CA_AgentV ca-user-membership-find <user>
        2. Run pki -n CA_AuditV ca-user-membership-find <user>
    :ExpectedResults:
        1. Command should not show the user membership with CA_AgentV.
        2. Command should not show the user membership with CA_AuditV.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = constants.CA_ADMIN_USERNAME
    group = 'Administrators'

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(admins),
                                 extra_args='{} "{}"'.format(user, group))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Group: ' in result['stdout']
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()
        else:
            error = "ForbiddenException: Authorization Error"
            assert error in result['stderr']
            log.info("Successfully run: {}".format(result['cmd']))


@pytest.mark.parametrize("admins", ['CA_AdminE', 'CA_AgentE', 'CA_AuditE'])
def test_pki_ca_user_membership_find_with_expired_certs(ansible_module, admins):
    """
    :Title: Test pki ca-user-membership-find, find membership of a user with CA_AdminE,
    :Description: Command should not show user membership with CA_AdminE.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Run pki -n CA_AdminE ca-user-membership-find <user>
        2. Run pki -n CA_AgentE ca-user-membership-find <user>
        3. Run pki -n CA_AuditE ca-user-membership-find <user>
    :ExpectedResults:
        1. Command should fail with the user CA_AdminE
        2. Command should fail with the user CA_AgentE
        3. Command should fail with the user CA_AuditE
    :Automated: Yes
    :CaseComponent: \-
    """
    user = constants.CA_ADMIN_USERNAME
    group = 'Administrators'

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(admins),
                                 extra_args='{} "{}"'.format(user, group))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Group: ' in result['stdout']
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()
        else:
            assert "SEVERE: FATAL: SSL alert received: CERTIFICATE_EXPIRED\nIOException: " \
                   "SocketException cannot read on socket: Error reading from socket: " \
                   "(-12269) SSL peer rejected your certificate as expired." in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))


def test_pki_ca_user_membership_find_with_ca_operatorv(ansible_module):
    """
    :Title: Test pki ca-user-membership-find, find membership of a user with CA_OperatorV.
    :Description: Command should not show the user membership with CA_OperatorV.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add CA_OperatorV User, issue certificate to user.
        2. Add operator group, add user to group.
        3. Import certificate.
        4. Run pki -n CA_OperatorV ca-user-membership-find <user>
    :ExpectedResults:
        1. Command should not show the user membership with CA_OperatorV.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'CA_OperatorV'
    fullName = 'CA OperatorV'
    t_user = 'TestE3{}'.format(random.randint(111, 9999))
    t_full_name = 'User {}'.format(user)
    group = 'Operator'
    subject = 'UID={},CN={}'.format(user, fullName)
    group_add = basic_pki_cmd + ' ca-group-add {} --description "Operator Group"'.format(group)
    user_add_to_group = basic_pki_cmd + " ca-user-membership-add {} {}".format(t_user, group)

    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    userop.add_user(ansible_module, 'add', userid=t_user, user_name=t_full_name)
    ansible_module.command(group_add)
    ansible_module.command(user_add_to_group)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 profile='caUserCert',
                                                 keysize=2048)
    log.info("Generated certificate for the user, Cert ID: {}".format(cert_id))
    if cert_id:
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

    user_membership_find = ansible_module.pki(cli=pki_cmd,
                                              nssdb=constants.NSSDB,
                                              dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                              port=constants.CA_HTTP_PORT,
                                              hostname=constants.MASTER_HOSTNAME,
                                              certnick='"{}"'.format(user),
                                              extra_args='{} "Administrators"'.format(t_user))
    for result in user_membership_find.values():
        if result['rc'] == 0:
            log.info('Failed to run: {}'.format(result['cmd']))
            pytest.fail('Failed to ran: {}'.format(result['cmd']))
        else:
            error = "ForbiddenException: Authorization Error"
            assert error in result['stderr']
            log.info('Successfully ran {}.'.format(result['cmd']))
    userop.remove_user(ansible_module, user)
    userop.remove_user(ansible_module, t_user)
    ansible_module.command(client_cert_del + user)


@pytest.mark.skip(reason="Pytest-ansible do not support i18n")
@pytest.mark.parametrize('full_name', ["ÖrjanÄke", "Éric Têko"])
def test_pki_ca_user_membership_find_with_i18n_chars(ansible_module, full_name):
    """
    :Title: Test pki ca-user-membership-find, find membership of a user with i18n characters.
    :Description: Command should show the user membership with i18n characters.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add user with i18n chars,
        2. Add user to different groups.
        3. Run pki ca-user-membership-find <user>
    :ExpectedResults:
        1. Verify whether pki ca-user-membership-find, should show the user with i19n characters.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'testuser03'
    fullName = full_name
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    membership1 = ["Certificate Manager Agents", "Registration Manager Agents",
                   "Subsystem Group", "Trusted Managers", "Administrators", "Auditors"]

    for i in membership1:
        cmd_out = ansible_module.pki(cli='ca-user-membership-add',
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='{} "{}"'.format(user, i))

        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Added membership in "{}"'.format(i) in result['stdout']
                assert 'Group: {}'.format(i) in result['stdout']
                log.info("Successfully run: {}".format(result['cmd']))
            else:
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()
    for i in membership1:
        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='{} "{}"'.format(user, i))
        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Deleted membership in group "{}"'.format(i) in result['stdout']
                log.info("Successfully run: {}".format(result['cmd']))
            if result['rc'] >= 1:
                error = "ForbiddenException: Authorization Error"
                assert error in result['stderr']
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_membership_find_when_uid_not_asso_with_grp(ansible_module):
    """
    :Title: Test pki ca-user-membership-find, find membership of a user when uid is not associated with a group.
    :Description: Command should show the pki ca-user-membership-find position of the user when uid is not associated
    with a group, should fail
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add User, Issue certificate to the user.
        2. Import user certificate to the client db.
        3. Run pki -n <user> ca-user-membership-find
    :ExpectedResults:
        1. Command should not show the user when user is not associated with any group.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'testuser05'
    fullName = 'Test user05'
    subject = "UID={},CN={}".format(user, fullName)

    t_user = 'tuser02'
    t_fullName = 'TUser02'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    userop.add_user(ansible_module, 'add', userid=t_user, user_name=t_fullName)
    user_add_to_group = basic_pki_cmd + " ca-user-membership-add {} {}".format(t_user, 'Administrators')
    ansible_module.command(user_add_to_group)

    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 profile='caUserCert',
                                                 keysize=2048)
    log.info("Generated certificate for the user, Cert ID: {}".format(cert_id))
    if cert_id:
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
    user_membership_find = ansible_module.pki(cli=pki_cmd,
                                              nssdb=constants.NSSDB,
                                              dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                              port=constants.CA_HTTP_PORT,
                                              hostname=constants.MASTER_HOSTNAME,
                                              certnick='"{}"'.format(user),
                                              extra_args='{}'.format(t_user))
    for result in user_membership_find.values():
        if result['rc'] == 0:
            log.info('Failed to run: {}'.format(result['cmd']))
            pytest.fail('Failed to ran: {}'.format(result['cmd']))
        else:
            error = "ForbiddenException: Authorization Error"
            assert error in result['stderr']
            log.info('Successfully ran {}.'.format(result['cmd']))
    userop.remove_user(ansible_module, user)
    userop.remove_user(ansible_module, t_user)
    ansible_module.command(client_cert_del + user)
