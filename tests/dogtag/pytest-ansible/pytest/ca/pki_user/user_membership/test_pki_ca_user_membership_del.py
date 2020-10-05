#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI CA-USER-MEMBERSHIP-DEL CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki user commands needs to be tested:
#   pki ca-user-membership-del
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
import re
import random

import pytest
import sys
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


pki_cmd = "ca-user-membership-del"
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
                                   constants.PROTOCOL_UNSECURE,
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


@pytest.mark.parametrize('args', ['--help', '', 'asdfa'])
def test_pki_ca_user_membership_del_with_help_option(ansible_module, args):
    """
    :Title: Test pki ca-user-membership-del with --help, '' and asdfa
    :Description: Command should add user pki ca-user-membership-del --help options
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-user-membership-del --help
        2. Run pki ca-user-membership-del ''
        3. Run pki ca-user-membership-del asdfa
    :ExpectedResults:
        1. Verify whether pki ca-user-membership-del --help command should show help options.
        1. Verify whether pki ca-user-membership-del '' should throw an error.
        1. Verify whether pki ca-user-membership-del asdfa should throw an error.
    :Automated: Yes
    :CaseComponent: \-
    """

    cmd = 'pki {} {}'.format(pki_cmd, args)

    cmd_out = ansible_module.command(cmd)

    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'usage: {} <User ID> <Group ID> [OPTIONS...]'.format(pki_cmd) in result['stdout']
            assert re.search('--help\s+Show help message', result['stdout'])
            log.info("Successfully run: {}".format(result['cmd']))
        elif args in ['', 'asdfa']:
            assert 'Incorrect number of arguments specified.' in result['stderr']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()


def test_pki_ca_user_membership_del_user_added_in_diff_groups(ansible_module):
    """
    :Title: Test pki ca-user-membership-del, when user added in different groups.
    :Description: Command should add user pki ca-user-membership-del, when user added in different groups
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add user.
        2. Add user to multiple groups.
        3. Run pki ca-user-membership-del <user> <group>
    :ExpectedResults:
        1. Verify whether pki ca-user-membership-del, when user is added in different groups.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'testuser01'
    fullName = 'Test User01'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    membership = ["Certificate Manager Agents", "Registration Manager Agents",
                  "Subsystem Group", "Trusted Managers", "Administrators", "Auditors",
                  "ClonedSubsystems", "Security Domain Administrators",
                  "Enterprise CA Administrators", "Enterprise KRA Administrators",
                  "Enterprise OCSP Administrators", "Enterprise TKS Administrators",
                  "Enterprise RA Administrators", "Enterprise TPS Administrators"]
    for i in membership:
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
    find_out = ansible_module.pki(cli='ca-user-membership-find',
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  port=constants.CA_HTTP_PORT,
                                  hostname=constants.MASTER_HOSTNAME,
                                  certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                  extra_args='{}'.format(user))
    for result in find_out.values():
        if result['rc'] == 0:
            for i in membership:
                assert 'Group: {}'.format(i) in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()

    for j in membership:
        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='{} "{}"'.format(user, j))
        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Deleted membership in group "{}"'.format(j) in result['stdout']
                log.info("Successfully run: {}".format(result['cmd']))
            else:
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_membership_del_mem_added_in_many_grps(ansible_module):
    """
    :Title: Test pki ca-user-membership-del, when user is added to many groups
    :Description: Command should add user pki ca-user-membership-del, when user is added to many groups
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1.
    :ExpectedResults:
        1. Verify whether pki ca-user-membership-del should delete the user who is added in many groups
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'testuser02'
    fullName = "Test User02"
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    membership = ["Certificate Manager Agents", "Registration Manager Agents",
                  "Subsystem Group", "Trusted Managers", "Administrators", "Auditors",
                  "Enterprise RA Administrators", "Enterprise TPS Administrators"]

    for i in membership:
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
    find_out = ansible_module.pki(cli='ca-user-membership-find',
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  port=constants.CA_HTTP_PORT,
                                  hostname=constants.MASTER_HOSTNAME,
                                  certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                  extra_args='{}'.format(user))
    for result in find_out.values():
        if result['rc'] == 0:
            for i in membership:
                assert 'Group: {}'.format(i) in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()

    for j in membership:
        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='{} "{}"'.format(user, j))
        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Deleted membership in group "{}"'.format(j) in result['stdout']
                log.info("Successfully run: {}".format(result['cmd']))
            else:
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_membership_del_when_groupid_is_missing(ansible_module):
    """
    :Title: Test pki ca-user-membership-del, when groupID is missing while deleting the user, should fail.
    :Description: Command should add user pki ca-user-membership-del, when groupID is missing while deleting the user.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults:
        1. Verify whether pki ca-user-membership-del, should throws the error while userID is missing.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = constants.CA_ADMIN_USERNAME
    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(user))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Deleted membership in group' in result['stdout']
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()
        else:
            error = "Incorrect number of arguments specified."
            assert error in result['stderr']
            log.info("Successfully run: {}".format(result['cmd']))


def test_pki_ca_user_membership_del_while_userid_is_missing(ansible_module):
    """
    :Title: Test pki ca-user-membership-del, while userID is missing while deleting a user from a group.
    :Description: Command should add user pki ca-user-membership-del, while userID is missing while deleting a user from a group.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults: Verify whether pki ca-user-membership-del, should throw the error while userID is missing.
    :Automated: Yes
    :CaseComponent: \-
    """
    group = 'Administrators'

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(group))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Deleted membership in group' in result['stdout']
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()
        else:
            error = "Incorrect number of arguments specified."
            assert error in result['stderr']
            log.info("Successfully run: {}".format(result['cmd']))


@pytest.mark.parametrize("admins", ['CA_AdminR', 'CA_AgentR', 'CA_AuditR'])
def test_pki_ca_user_membership_del_using_revoked_certs(ansible_module, admins):
    """
    :Title: Test pki ca-user-membership-del, delete using CA_AdminR,CA_AgentR, CA_AuditR should fail.
    :Description: Command should not delete user from group using CA_AdminR,CA_AgentR, CA_AuditR.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1.
    :ExpectedResults:
        1. Command should not delete using CA_AdminR,CA_AgentR, CA_AuditR.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'testuser03'
    fullName = 'Test User03'
    group = 'Administrators'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    cmd_out = ansible_module.pki(cli='ca-user-membership-add',
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} "{}"'.format(user, group))

    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added membership in "{}"'.format(group) in result['stdout']
            assert 'Group: {}'.format(group) in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()
    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(admins),
                                 extra_args='{} "{}"'.format(user, group))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added membership in "{}"'.format(group) in result['stdout']
            assert 'Group: {}'.format(group) in result['stdout']
            log.error('Failed to run: {}'.format(result['cmd']))

        if result['rc'] >= 1:
            error = "PKIException: Unauthorized"
            assert error in result['stderr']
            log.info("Successfully run: {}".format(result['cmd']))
    userop.remove_user(ansible_module, user)


@pytest.mark.parametrize("admins", ['CA_AdminE', 'CA_AgentE', 'CA_AuditE'])
def test_pki_ca_user_membership_del_using_expired_certs(ansible_module, admins):
    """
    :Title: Test pki ca-user-membership-del, delete using CA_AdminE, CA_AgentE, CA_AuditE.
    :Description: Command should add user pki ca-user-membership-del, delete using CA_AdminE,CA_AgentE, CA_AuditE.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults:
        1. Command should not delete using CA_AdminE, CA_AgentE, CA_AuditE throws error.
    :Automated: Yes
    :CaseComponent: \-
    """

    user = 'testuser04'
    fullName = 'Test User04'
    group = 'Administrators'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    cmd_out = ansible_module.pki(cli='ca-user-membership-add',
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} "{}"'.format(user, group))

    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added membership in "{}"'.format(group) in result['stdout']
            assert 'Group: {}'.format(group) in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()
    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(admins),
                                 extra_args='{} "{}"'.format(user, group))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Deleted membership in group "{}"'.format(group) in result['stdout']
            log.error('Failed to run: {}'.format(result['cmd']))
            pytest.fail()
        if result['rc'] >= 1:
            assert "SEVERE: FATAL: SSL alert received: CERTIFICATE_EXPIRED\nIOException: " \
                   "SocketException cannot read on socket: Error reading from socket: " \
                   "(-12269) SSL peer rejected your certificate as expired." in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
    userop.remove_user(ansible_module, user)


@pytest.mark.parametrize("admins", ['CA_AgentV', 'CA_AuditV'])
def test_pki_ca_user_membership_del_using_valid_certs(ansible_module, admins):
    """
    :Title: Test pki ca-user-membership-del CLI delete using CA_AgentV CA_AuditV.
    :Description: Command should add user pki ca-user-membership-del CLI delete using CA_AgentV, CA_AuditV.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1.
    :ExpectedResults:
        1. Verify whether pki ca-user-membership-del, should not delete using CA_AdminV, CA_AuditV.
    :Automated: Yes
    :CaseComponent: \-
    """

    user = 'testuser05'
    fullName = 'Test User05'
    group = 'Administrators'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    cmd_out = ansible_module.pki(cli='ca-user-membership-add',
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} "{}"'.format(user, group))

    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added membership in "{}"'.format(group) in result['stdout']
            assert 'Group: {}'.format(group) in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()
    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(admins),
                                 extra_args='{} "{}"'.format(user, group))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Deleted membership in group "{}"'.format(group) in result['stdout']
            log.error('Failed to run: {}'.format(result['cmd']))
        if result['rc'] >= 1:
            error = "ForbiddenException: Authorization Error"
            assert error in result['stderr']
            log.info("Successfully run: {}".format(result['cmd']))

    userop.remove_user(ansible_module, user)


def test_pki_ca_user_membership_del_using_ca_operatorv(ansible_module):
    """
    :Title: Test pki ca-user-membership-del CLI delete using CA_OperatorV.
    :Description: Command should add user pki ca-user-membership-del CLI delete using CA_OperatorV.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults:
        1. Verify whether pki ca-user-membership-del, should not delete using CA_OperatorV, throws error.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'CA_OperatorV'
    fullName = 'CA OperatorV'
    t_user = 'TestE3{}'.format(random.randint(111, 9999))
    t_full_name = 'User {}'.format(user)
    group = 'Operator'
    subject = 'UID={},CN={},OU=Engineering,O=Example'.format(user, fullName)
    group_add = basic_pki_cmd + ' ca-group-add {} --description "Operator Group"'.format(group)
    user_add_to_group = basic_pki_cmd + " ca-user-membership-add {} {}".format(user, group)
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    userop.add_user(ansible_module, 'add', userid=t_user, user_name=t_full_name)
    ansible_module.command(group_add)
    ansible_module.command(user_add_to_group)
    user_add_to_group2 = basic_pki_cmd + " ca-user-membership-add {} Administrators".format(t_user)
    ansible_module.command(user_add_to_group2)
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

    user_del_out = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.CA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(user),
                                      extra_args='{} "Administrators"'.format(t_user))
    for result in user_del_out.values():
        if result['rc'] == 0:
            log.error('Failed to run: {}'.format(result['cmd']))
            pytest.fail('Failed to ran: {}'.format(result['cmd']))
        else:
            error = "ForbiddenException: Authorization Error"
            assert error in result['stderr']
            log.info('Successfully ran {}.'.format(result['cmd']))
    userop.remove_user(ansible_module, user)
    userop.remove_user(ansible_module, t_user)
    ansible_module.command('pki -d {} -c {} client-cert-del '
                           '{}'.format(constants.NSSDB, constants.CLIENT_DIR_PASSWORD, user))


@pytest.mark.skip(reason="Pytest ansible do not support i18n.")
@pytest.mark.parametrize("users", ['testuser6', 'ÖrjanÄke'])
def test_pki_ca_user_membership_del_CA_with_i18n_char(ansible_module, users):
    """
    :Title: Test pki ca-user-membership-del, delete membership when userName is i18n char.
    :Description: Command should add user pki ca-user-membership-del, delete membership when userName is i18n char.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1.
    :ExpectedResults:
        1. Command should delete user membership with i18n char.
    :Automated: Yes
    :CaseComponent: \-
    """
    group = 'dadministʁasjɔ̃'
    description = "Admininstartors in French"
    user = users
    fullName = "User {}".format(user)
    group_add = basic_pki_cmd + ' ca-group-add {} --description "{}"'.format(group, description)

    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    group_add_out = ansible_module.command(group_add)

    user_add_to_group = basic_pki_cmd + ' ca-user-membership-add {} "{}"'.format(user, group)
    user_add_out = ansible_module.command(user_add_to_group)
    for result in user_add_out.values():
        if result['rc'] == 0:
            assert 'Added membership in "{}"'.format(group) in result['stdout']
            assert 'Group: {}'.format(group) in result['stdout']
        else:
            log.error("Failed to run: {}".format(result['cmd']))
    user_del_out = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.CA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                      extra_args='{} "{}"'.format(user, group))
    for result in user_del_out.values():
        if result['rc'] == 0:
            assert 'Deleted membership in group "{}"'.format(group) in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            log.info('Failed to run: {}'.format(result['cmd']))
            pytest.fail('Failed to ran: {}'.format(result['cmd']))
    group_del = basic_pki_cmd + ' ca-group-add {}'.format(group)
    ansible_module.command(group_del)
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_membership_del_when_user_not_asso_with_any_group(ansible_module):
    """
    :Title: Test pki ca-user-membership-del CLI when user not associated with any group
    :Description: Command should add user pki ca-user-membership-del CLI when user not associated with any group.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add user, add cert to user.
        2. Import certificate to client db.
        3. Run pki -n <user> ca-user-membership-del <user> "Administrators"
    :ExpectedResults:
        1. Command should not delete the membership when user not associated with any group.
    :Automated: Yes
    :CaseComponent: \-
    """

    user = 'testuser7'
    fullName = "Test User7"
    t_user = 'tuser1'
    t_fullname = "T User1"
    group = 'Administrators'
    userop.add_user(ansible_module, 'add', userid=t_user, user_name=t_fullname)
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    subject = 'UID={},CN={}'.format(user, fullName)
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
    cmd_out = ansible_module.pki(cli='ca-user-membership-add',
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} "{}"'.format(t_user, group))

    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added membership in "{}"'.format(group) in result['stdout']
            assert 'Group: {}'.format(group) in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()
    user_del_out = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.CA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(user),
                                      extra_args='{} "{}"'.format(t_user, group))
    for result in user_del_out.values():
        if result['rc'] == 0:
            log.info('Failed to run: {}'.format(result['cmd']))
            pytest.fail('Failed to ran: {}'.format(result['cmd']))
        else:
            error = "ForbiddenException: Authorization Error"
            assert error in result['stderr']
            log.info('Successfully ran {}.'.format(result['cmd']))
    userop.remove_user(ansible_module, user)
    userop.remove_user(ansible_module, t_user)
    ansible_module.command('pki -d {} -c {} client-cert-del '
                           '{}'.format(constants.NSSDB, constants.CLIENT_DIR_PASSWORD, user))


def test_pki_ca_user_membership_del_when_user_not_in_cert_man_agents(ansible_module):
    """
    :Title: User deleted from the Certificate Manager Agents group can not approve certificate requests
    :Description: Command should add user pki ca-user-membership-del, User deleted from the
    Certificate Manager Agents group can not approve certificate requests.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add user, add cert to user.
        2. Import user certificate.
        3. Approve certificate request using newly added user.
    :ExpectedResults:
        1. Command should not approve the certificate if it is not present in the Certificate Manager Agents.
    :Automated: Yes
    :CaseComponent: \-
    """

    user = 'testuser08'
    fullName = "Test user08"
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    subject = 'UID={},CN={}'.format(user, fullName)
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

    cert_id2 = userop.process_certificate_request(ansible_module, subject=subject,
                                                  profile='caUserCert', approver_nickname=user,
                                                  keysize=2048)
    assert cert_id2 is None
    log.info("Successfully run: User not able to approve certificate if user not exists in the CMA.")
    userop.remove_user(ansible_module, user)
    ansible_module.command('pki -d {} -c {} client-cert-del '
                           '{}'.format(constants.NSSDB, constants.CLIENT_DIR_PASSWORD, user))
