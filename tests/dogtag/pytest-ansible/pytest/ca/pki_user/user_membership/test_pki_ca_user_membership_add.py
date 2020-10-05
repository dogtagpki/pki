#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI CA-USER-MEMBERSHIP-ADD CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki user commands needs to be tested:
#   pki ca-user-membership-add
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

pki_cmd = "ca-user-membership-add"
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


def test_pki_ca_user_membership_command(ansible_module):
    """
    :Title:Test pki user-membership command
    :Description: Command should show pki user-membership options and uses.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. pki ca-user-membership
    :ExpectedResults:
        1. Verify whether pki user-membership should show the options and uses.
    :Automated: Yes
    :CaseComponent: \-
    """
    membership_cmd = 'pki ca-user-membership'
    cmd_out = ansible_module.command(membership_cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Commands:" in result['stdout']
            assert re.search("ca-user-membership-find\s+Find user memberships", result['stdout'])
            assert re.search("ca-user-membership-add\s+Add user membership", result['stdout'])
            assert re.search("ca-user-membership-del\s+ Remove user membership", result['stdout'])
            log.info("Successfully run: {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run {}".format(result['cmd']))
            pytest.fail()


@pytest.mark.parametrize('args', ['--help', ''])
def test_pki_ca_user_membership_add_help_command(ansible_module, args):
    """
    :Title:Test pki ca-user-membership-add with '' and --help
    :Description: Pki ca-user-membership-add with '' and --help.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-user-membership-add --help
        2. Run pki ca-user-membership-add ''
    :ExpectedResults:
        1. Verify whether pki ca-user-membership-add --help should show the options and uses.
        1. It should throw an exception.
    :Automated: Yes
    :CaseComponent: \-
    """
    help_cmd = 'pki {} {}'.format(pki_cmd, args)
    cmd_out = ansible_module.command(help_cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "usage: ca-user-membership-add <User ID> <Group ID> [OPTIONS...]" in result['stdout']
            assert re.search("--help\s+Show help message.", result['stdout'])
            log.info("Successfully run: {}".format(" ".join(result['cmd'])))
        elif args == '':
            assert 'Incorrect number of arguments specified.' in result['stderr']
            log.info("Successfully run: {}".format(" ".join(result['cmd'])))
        else:
            pytest.fail()


@pytest.mark.parametrize('groups', ["Certificate Manager Agents", "Registration Manager Agents",
                                    "Subsystem Group", "Trusted Managers", "Administrators",
                                    "Auditors", "ClonedSubsystems", "Security Domain Administrators",
                                    "Enterprise CA Administrators", "Enterprise KRA Administrators",
                                    "Enterprise OCSP Administrators", "Enterprise TKS Administrators",
                                    "Enterprise RA Administrators", "Enterprise TPS Administrators"])
def test_pki_ca_user_membership_add_users_to_available_groups(ansible_module, groups):
    """
    :Title:Test pki user-membsership-add, add users to available groups using valid admin user.
    :Description: Add users to available groups using valid admin user.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1.
    :ExpectedResults:
        1. Verify whether pki ca-user-membership-add, add users to available groups using valid admin user.
    :Automated: Yes
    :CaseComponent: \-
    """

    user = 'testuser01'
    fullName = 'Test User01'

    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} "{}"'.format(user, groups))

    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added membership in "{}"'.format(groups) in result['stdout']
            assert 'Group: {}'.format(groups) in result['stdout']
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
                                  extra_args='{} "{}"'.format(user, groups))

    for result in find_out.values():
        if result['rc'] == 0:
            assert 'Group: {}'.format(groups) in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_membership_add_user_to_all_available_groups(ansible_module):
    """
    :Title:Test pki ca-user-membership-add CLI add user to all available groups.
    :Description: Add users to all available groups.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-user-membership-add <user> Administrators
        2. Run pki ca-user-membership-add <user> "Certificate Manager Agents"
        3. Run pki ca-user-membership-add <user> "Registration Manager Agents"
        4. Run pki ca-user-membership-add <user> "Subsystem Group"
        5. Run pki ca-user-membership-add <user> "Trusted Managers"
        6. Run pki ca-user-membership-add <user> Auditors
        7. Run pki ca-user-membership-add <user> ClonedSubsystems
        8. Run pki ca-user-membership-add <user> "Security Domain Administrators"
        9. Run pki ca-user-membership-add <user> "Enterprise CA Administrators"
        10. Run pki ca-user-membership-add <user> "Enterprise KRA Administrators"
        11. Run pki ca-user-membership-add <user> "Enterprise OCSP Administrators"
        12. Run pki ca-user-membership-add <user> "Enterprise TKS Administrators"
        13. Run pki ca-user-membership-add <user> "Enterprise RA Administrators"
        14. Run pki ca-user-membership-add <user>  "Enterprise TPS Administrators"
    :ExpectedResults: 
        1.Verify whether pki ca-user-membership-add, add users to all available groups.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'testuser02'
    fullName = 'Test user02'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    group_list = ["Certificate Manager Agents", "Registration Manager Agents",
                  "Subsystem Group", "Trusted Managers", "Administrators",
                  "Auditors", "ClonedSubsystems", "Security Domain Administrators",
                  "Enterprise CA Administrators", "Enterprise KRA Administrators",
                  "Enterprise OCSP Administrators", "Enterprise TKS Administrators",
                  "Enterprise RA Administrators", "Enterprise TPS Administrators"]
    for i in group_list:
        cmd_out = ansible_module.pki(cli=pki_cmd,
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
            for i in group_list:
                assert 'Group: {}'.format(i) in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_membership_add_to_same_group_multiple_time(ansible_module):
    """
    :Title:Test pki user-membsership-add, add user to same group multiple time.
    :Description: Add user to same group multiple time.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-user-membership-add <user> Administrators
        2. Run pki ca-user-membership-add <user> Administrators
    :ExpectedResults:
        1. Verify whether pki ca-user-membership-add, add user to same group multiple time.
    :Automated: Yes
    :CaseComponent: \-
    """

    user = 'testuser03'
    fullName = 'Test User03'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    for i in ['Administrators', 'Administrators']:
        cmd_out = ansible_module.pki(cli=pki_cmd,
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
            if result['rc'] >= 1:
                assert 'ConflictingOperationException: Attribute or value exists' in result['stderr']
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_membership_add_non_existing_group(ansible_module):
    """
    :Title:Test pki ca-user-membership-add, should not able to add user to non existing group.
    :Description: Command should not able to add user to non existing group.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. pki ca-user-membership-add <user> <non_existing_group>
    :ExpectedResults:
        1. Verify whether pki ca-user-membership-add, should not able to add user to non existing group.
    :Automated: Yes
    :CaseComponent: \-
    """
    group = "nonexisting_bogus_group"
    fullName = 'Test User04'
    user = 'testuser04'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    cmd_out = ansible_module.pki(cli=pki_cmd,
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
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()
        if result['rc'] >= 1:
            assert "GroupNotFoundException: Group {} not found".format(group) in result['stderr']
            log.info("Successfully run: {}".format(result['cmd']))

    userop.remove_user(ansible_module, user)


@pytest.mark.skip(reason="Pytest ansible do not support i18n chars.")
def test_pki_ca_user_membership_add_user_with_i18_char(ansible_module):
    """
    :Title:Test pki ca-user-membership-add, should able to add user's full name with i18 characters.
    :Description: Should able to add user's full name with i18 characters.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1.
    :ExpectedResults:
        1. Verify whether pki ca-user-membership-add, should able to add user's full name with i18 characters.
    :Automated: Yes
    :CaseComponent: \-
    """

    fullName = 'ÖrjanÄke'
    user = 'testuser05'
    group = 'Administrators'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    cmd_out = ansible_module.pki(cli=pki_cmd,
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
        if result['rc'] >= 1:
            assert "GroupNotFoundException: Group {} not found".format(group) in result['stderr']
    userop.remove_user(ansible_module, user)


@pytest.mark.skip(reason="Pytest ansible do not support i18n chars.")
def test_pki_ca_user_membership_add_user_id_with_i18_char(ansible_module):
    """
    :Title:Test pki ca-user-membership-add, should able to add user with user-id as i18 characters.
    :Description: Command should able to add user with user-id as i18 characters.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults: 
        Verify whether pki ca-user-membership-add, should able to add user with user-id as i18 characters.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'Éric Têko{}'.format(str(random.randint(111111, 999999999)))
    fullName = 'testuser06'
    group = 'Administrators'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

    cmd_out = ansible_module.pki(cli=pki_cmd,
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
        if result['rc'] >= 1:
            assert "GroupNotFoundException: Group {} not found".format(group) in result['stderr']
    userop.remove_user(ansible_module, user)


@pytest.mark.parametrize("admins", ['CA_AdminR', 'CA_AgentR'])
def test_pki_ca_user_membership_add_with_revoked_certs(ansible_module, admins):
    """
    :Title: pki ca-user-membership-add, should not able to add using revoked admin certificate.
    :Description: Command should not able to add users using revoked admin certificate.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults: 
        1. Verify whether pki ca-user-membership-add, should not able to add users using revoked certificate.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'testuser07'
    fullName = 'Test User07'
    group = 'Administrators'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

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
            log.info("Successfully run: {}".format(result['cmd']))
        if result['rc'] >= 1:
            error = "PKIException: Unauthorized"
            assert error in result['stderr']
    userop.remove_user(ansible_module, user)


@pytest.mark.parametrize("admins", ['CA_AdminE', 'CA_AgentE'])
def test_pki_ca_user_membership_add_with_expired_certs(ansible_module, admins):
    """
    :Title: pki ca-user-membership-add, should not able to add membership using expired admin cert
    :Description: pki ca-user-membership-add command, should not able to add membership using expired admin cert.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults: 
        1. Verify whether pki ca-user-membership-add, should not able to add membership using expired admin cert
    :Automated: Yes
    :CaseComponent: \-
    """

    user = 'testuser08'
    fullName = 'Test User08'
    group = 'Administrator'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

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
            log.info("Failed to run: {}".format(result['cmd']))
            pytest.fail()
        if result['rc'] >= 1:
            assert "SEVERE: FATAL: SSL alert received: CERTIFICATE_EXPIRED\nIOException: " \
                   "SocketException cannot read on socket: Error reading from socket: " \
                   "(-12269) SSL peer rejected your certificate as expired." in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
    userop.remove_user(ansible_module, user)


@pytest.mark.parametrize("admins", ['CA_AuditV', 'CA_AgentV'])
def test_pki_ca_user_membership_with_valid_user_certs(ansible_module, admins):
    """
    :Title: pki ca-user-membership-add, should not able to add user membership using AuditV user.
    :Description: pki ca-user-membership-add, should not able to add user membership using AuditV user.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. 
    :ExpectedResults: 
        1. Verify whether pki ca-user-membership-add, should not able to add user membership using AuditV user.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'testuser09'
    fullName = 'Test User09'
    group = 'Administrator'

    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)

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
            log.info("Successfully run: {}".format(result['cmd']))
        if result['rc'] >= 1:
            error = "ForbiddenException: Authorization Error"
            assert error in result['stderr']
    userop.remove_user(ansible_module, user)


def test_pki_ca_user_membership_add_with_operator_user(ansible_module):
    """
    :Title: pki ca-user-membership-add, should not able to add user membership using Operator user.
    :Description: Add users to available groups using valid admin user.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. 
    :ExpectedResults: 
        1. Verify whether pki ca-user-membership-add, add user membership using Operator user.
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
            log.info('Failed to run: {}'.format(result['cmd']))
            pytest.fail('Failed to ran: {}'.format(result['cmd']))
        else:
            error = "ForbiddenException: Authorization Error"
            assert error in result['stderr']
            log.info('Successfully ran {}.'.format(result['cmd']))
    userop.remove_user(ansible_module, user)
    userop.remove_user(ansible_module, t_user)
    ansible_module.command(basic_pki_cmd + " ca-group-del {}".format(group))
    ansible_module.command('pki -d {} -c {} client-cert-del '
                           '{}'.format(constants.NSSDB, constants.CLIENT_DIR_PASSWORD, user))


def test_pki_ca_user_membership_add_admin_users_can_create_a_new_user(ansible_module):
    """
    :Title: pki ca-user-membership-add, user associated with Administrator group only can create a new user.
    :Description: pki ca-user-membership-add, user associated with Administrator group only can create a new user.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1.
    :ExpectedResults:
        1. Verify whether pki ca-user-membership-add, user associated with Administrator group only can create a new user.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'testuser10'
    fullName_user = 'Test user10'
    admin_user = 'adminuser'
    admin_user_fullName = 'Test Adminuser'
    subject = 'UID={},CN={}'.format(admin_user, admin_user_fullName)
    group = 'Administrators'
    userop.add_user(ansible_module, 'add', userid=admin_user, user_name=admin_user_fullName)

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} "{}"'.format(admin_user, group))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added membership in "{}"'.format(group) in result['stdout']
            assert 'Group: {}'.format(group) in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
            cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                         profile='caUserCert',
                                                         keysize=2048)
            log.info("Generated certificate for the user, Cert ID: {}".format(cert_id))
            if cert_id:
                cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
                add_cert_to_user(ansible_module, admin_user, subject, cert_id, cert_subject)
                import_cert = basic_pki_cmd + ' client-cert-import {} --serial {}'.format(admin_user, cert_id)
                import_out = ansible_module.command(import_cert)
                for res in import_out.values():
                    if res['rc'] == 0:
                        assert 'Imported certificate "{}"'.format(admin_user) in res['stdout']
                        log.info('Imported certificate "{}"'.format(admin_user))
                    else:
                        log.error("Failed to import the certificate.")
                        pytest.fail("Failed to import certificate.")
        if result['rc'] >= 1:
            error = "ForbiddenException: Authorization Error"
            assert error in result['stderr']

    cmd_out = ansible_module.pki(cli='ca-user-add',
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(admin_user),
                                 extra_args='{} --fullName "{}"'.format(user, fullName_user))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added user "{}"'.format(user) in result['stdout']
            assert 'User ID: {}'.format(user) in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()
    userop.remove_user(ansible_module, user)
    userop.remove_user(ansible_module, admin_user)
    ansible_module.command('pki -d {} -c {} client-cert-del '
                           '{}'.format(constants.NSSDB, constants.CLIENT_DIR_PASSWORD, admin_user))


def test_pki_ca_user_membership_add_cma_can_approve_cert_req(ansible_module):
    """
    :Title: user associated with Certificate Manager Agents group only can approve certificate request.
    :Description: pki ca-user-membership-add, user associated with Certificate Manager Agents 
    group only can approve certificate request.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults:
        1. User with Certificate Manager Agents group only can approve certificate request.
    :Automated: Yes
    :CaseComponent: \-
    """
    agent_user = 'agent_user'
    agent_fullName = 'Test Agent User'
    group = "Certificate Manager Agents"
    userop.add_user(ansible_module, 'add', userid=agent_user, user_name=agent_fullName)
    subject = 'UID={},CN={}'.format(agent_user, agent_fullName)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize='2048', profile='caUserCert')
    if cert_id:
        log.info("Generated certificate with cert ID: {}".format(cert_id))
        cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
        add_cert_to_user(ansible_module, agent_user, subject, cert_id, cert_subject)
        cmd_out = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='{} "{}"'.format(agent_user, group))
        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Added membership in "{}"'.format(group) in result['stdout']
                assert 'Group: {}'.format(group) in result['stdout']
                log.info("Successfully run: {}".format(result['cmd']))
        import_cert = basic_pki_cmd + ' client-cert-import {} --serial {}'.format(agent_user, cert_id)
        import_out = ansible_module.command(import_cert)
        for res in import_out.values():
            if res['rc'] == 0:
                assert 'Imported certificate "{}"'.format(agent_user) in res['stdout']
                log.info('Imported certificate "{}"'.format(agent_user))
            else:
                log.error("Failed to import the certificate.")
                pytest.fail("Failed to import certificate.")

        cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                     request_type='pkcs10', algo='rsa',
                                                     approver_nickname=agent_user,
                                                     keysize='2048', profile='caUserCert')
        assert cert_id is not None
    userop.remove_user(ansible_module, agent_user)


def test_pki_ca_user_membership_add_when_user_does_not_exists(ansible_module):
    """
    :Test: pki ca-user-membership-add, should not add membership to the user that does not exits.
    :Description: pki ca-user-membership-add, should not add membership to the user that does not exits.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults:
        1. Verify whether pki ca-user-membership-add, should not add membership to the user that does not exits.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'userNotExists_{}'.format(random.randint(000, 999999))
    group = 'Administrators'
    cmd_out = ansible_module.pki(cli=pki_cmd,
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
        if result['rc'] >= 1:
            error = "UserNotFoundException: User userNotExists not found"
            assert error in result['stderr']
            log.info("Successfully run: {}".format(result['cmd']))
