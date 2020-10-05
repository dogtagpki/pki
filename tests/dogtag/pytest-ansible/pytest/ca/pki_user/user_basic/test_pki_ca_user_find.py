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
import sys
import time
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

pki_cmd = "ca-user-find"
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
                                   constants.CA_HTTP_PORT,
                                   constants.PROTOCOL_UNSECURE, constants.CA_ADMIN_NICK)

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


def test_pki_ca_user_find_added_users(ansible_module):
    """
    :Title: Add valid users to the database to test the pki ca-user-find command
    :Description: Command should successfully add the users to the database
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults: Verify whether users are added to the database.
    :Automated: Yes
    :CaseComponent: \-
    """
    users = ['ca_agent1', 'abcdefghijklmnopqrstuvwxyx12345678', 'abc#', 'abc$',
             'abc@', 'abc?', '0']
    for user in users:
        full_name = "Test {}".format(user)
        userop.add_user(ansible_module, 'add', userid=user, user_name=full_name)
        log.info("Added user: {}".format(user))

    find_out = ansible_module.pki(cli=pki_cmd,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  port=constants.CA_HTTP_PORT,
                                  hostname=constants.MASTER_HOSTNAME,
                                  certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                  extra_args=' --size 100')
    for result in find_out.values():
        if result['rc'] == 0:
            for user in users:
                full_name = 'Test {}'.format(user)
                assert user in result['stdout']
                assert full_name in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail("")

    for user in users:
        userop.remove_user(ansible_module, user)


@pytest.mark.parametrize('args', ['--help', '', 'asdfa'])
def test_pki_ca_user_find_help_option(ansible_module, args):
    """
    :Title: test pki ca-user-find --help command
    :Description: Command should successfully show its option for pki ca-user-find command
            usage: ca-user-find [FILTER] [OPTIONS...]
                --help            Show help options
                --size <size>     Page size
                --start <start>   Page start
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults:
        1. Verify whether pki ca-user-find --help command shows all the options.
    :Automated: Yes
    :CaseComponent: \-
    """

    user_help_cmd_out = ansible_module.pki(cli=pki_cmd,
                                           nssdb=constants.NSSDB,
                                           dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                           port=constants.CA_HTTP_PORT,
                                           hostname=constants.MASTER_HOSTNAME,
                                           certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                           extra_args='{}'.format(args))
    for result in user_help_cmd_out.values():
        if args == '--help':
            assert "usage: {} [FILTER] [OPTIONS...]".format(pki_cmd) in result['stdout']
            assert "--size <size>     Page size" in result['stdout']
            assert "--start <start>   Page start" in result['stdout']
            assert re.search("--help\s+Show help message.", result['stdout'])
            log.info('Successfully ran : {}'.format(result['cmd']))
        elif args == '':
            time.sleep(20)
            log.info(result['stdout'])
            log.info(result['stderr'])
            assert 'Number of entries returned' in result['stdout']
        elif args == 'asdfa':
            assert '0 entries matched' in result['stdout']
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail("")


def test_pki_ca_user_find_with_size_five(ansible_module):
    """
    :Title: test pki ca-user-find with 5 user entries.
    :Description: Command should successfully show 5 user entries form the database.
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults:
        1. Verify whether pki ca-user-find should shows 5 users from the database.
    :Automated: Yes
    :CaseComponent: \-
    """

    user_find_cmd_out = ansible_module.pki(cli=pki_cmd,
                                           nssdb=constants.NSSDB,
                                           dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                           port=constants.CA_HTTP_PORT,
                                           hostname=constants.MASTER_HOSTNAME,
                                           certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                           extra_args=' --size 5')
    for result in user_find_cmd_out.values():
        if result['rc'] == 0:
            assert "Number of entries returned 5" in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error('Failed to run: {}'.format(result['cmd']))
            pytest.fail()


def test_pki_ca_user_find_with_size_zero(ansible_module):
    """
    :Title: test pki usre-find command with option --size as 0
    :Description: Command should successfully show zero entries form the database.
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults:
        1. Verify whether pki ca-user-find command should return 0 entries from the database.
    :Automated: Yes
    :CaseComponent: \-
    """

    user_find_cmd_out = ansible_module.pki(cli=pki_cmd,
                                           nssdb=constants.NSSDB,
                                           dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                           port=constants.CA_HTTP_PORT,
                                           hostname=constants.MASTER_HOSTNAME,
                                           certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                           extra_args=' --size 0')

    for result in user_find_cmd_out.values():
        if result['rc'] == 0:
            assert "Number of entries returned 0" in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error('Failed to run: {}'.format(result['cmd']))
            pytest.fail('')


@pytest.mark.parametrize("large_no", ["1000000", "9785300607", "32966839240041", '-1', 'abc', ''])
def test_pki_ca_user_find_with_large_size(ansible_module, large_no):
    """
    :Title: test ca-user-find command when passing different values like -1, abc, '',
            234234802, to --size option
    :Description: Command should successfully show entries in the database when value is 1000000,
            else it should throws the error for other values.
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults:
        1. Verify whether pki ca-user-find should shows the entries in the database when --size is valid
        value and for other values it should throws an Exception.
    :Automated: Yes
    :CaseComponent: \-
    """
    user_find_cmd_out = ansible_module.pki(cli=pki_cmd,
                                           nssdb=constants.NSSDB,
                                           dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                           port=constants.CA_HTTP_PORT,
                                           hostname=constants.MASTER_HOSTNAME,
                                           certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                           extra_args=' --size {}'.format(large_no))

    for result in user_find_cmd_out.values():
        if result['rc'] == 0:
            if int(large_no, 10) < 0:
                assert "Number of entries returned 0" in result['stdout']
                log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            if large_no.isdigit() or large_no.isalpha():
                error = 'NumberFormatException: For input string: "{}"'.format(large_no)
                assert error in result['stderr']
            elif large_no == '':
                assert 'MissingArgumentException: Missing argument for option: size' in \
                       result['stderr']
            else:
                log.error('Failed to run: {}'.format(result['cmd']))
                pytest.fail('')


@pytest.mark.parametrize("large_no", ["10", "0", "9785300607", "32966839240041", '-1', 'abc', ''])
def test_pki_ca_user_find_with_start_op(ansible_module, large_no):
    """
    :Title: test pki ca-user-find with --start value as 10.
    :Description: Command should successfully show users list from 10 onwards.
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults:
        1. Verify whether pki ca-user-find with --start value as 10 should shows the user from 11.
    :Automated: Yes
    :CaseComponent: \-
    """

    large_num = large_no

    user_find_cmd_out = ansible_module.pki(cli=pki_cmd,
                                           nssdb=constants.NSSDB,
                                           dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                           port=constants.CA_HTTP_PORT,
                                           hostname=constants.MASTER_HOSTNAME,
                                           certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                           extra_args=' --size {}'.format(large_no))

    for result in user_find_cmd_out.values():
        if result['rc'] == 0:
            if int(large_no, 10) < 0:
                assert "Number of entries returned 0" in result['stdout']
                log.info('Successfully ran : {}'.format(result['cmd']))
            elif int(large_no) == 10:
                assert "Number of entries returned 10" in result['stdout']
                assert "User ID" in result['stdout']
                assert "Full name" in result['stdout']
        else:
            if large_no.isdigit() or large_no.isalpha():
                error = 'NumberFormatException: For input string: "{}"'.format(large_no)
                assert error in result['stderr']
            elif large_no == '':
                assert 'MissingArgumentException: Missing argument for option: size' in \
                       result['stderr']
            else:
                log.error('Failed to run: {}'.format(result['cmd']))
                pytest.fail('')


@pytest.mark.parametrize("size,start", [("12", "12"), ("0", "12")])
def test_pki_ca_user_find_with_diff_size_and_start(ansible_module, size, start):
    """
    :Title: Test pki ca-user-find command, when --size=12 --start=12 and --size=0, --start=12
    :Description: Command should successfully show its option for pki user-add command
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults: Verify whether pki ca-user-find command, when --size=12 --start=12 and
            --size=0,--start=12.
    :Automated: Yes
    :CaseComponent: \-
    """
    for user in range(4):
        userid = 'testuser01_{}'.format(user)
        userop.add_user(ansible_module, 'add', userid=userid, user_name=userid, subsystem='ca')
    user_find_cmd_out = ansible_module.pki(cli=pki_cmd,
                                           nssdb=constants.NSSDB,
                                           dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                           port=constants.CA_HTTP_PORT,
                                           hostname=constants.MASTER_HOSTNAME,
                                           certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                           )

    total_user = re.search('([0-9]+)\s+entries matched', user_find_cmd_out.values()[0]['stdout']).group(1)
    user_find_cmd_out = ansible_module.pki(cli=pki_cmd,
                                           nssdb=constants.NSSDB,
                                           dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                           port=constants.CA_HTTP_PORT,
                                           hostname=constants.MASTER_HOSTNAME,
                                           certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                           extra_args=' --size {} --start {}'.format(size, start))

    # Output of this command will be size (total 12 )user certs starting from start [12th number].
    for result in user_find_cmd_out.values():
        if result['rc'] == 0:
            e_size = 0 if int(size) <= 0 else int(size)
            if e_size <= 0:
                assert 'Number of entries returned 0'.format(size) in result['stdout']
            else:
                out_no = int(total_user) - int(start)
                if e_size < out_no:
                    assert 'Number of entries returned {}'.format(size) in result['stdout']
                else:
                    assert 'Number of entries returned {}'.format(str(out_no)) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error('Failed to run: {}'.format(result['cmd']))
            pytest.fail('')

    for user in range(4):
        userid = 'testuser01_{}'.format(user)
        userop.remove_user(ansible_module, userid, subsystem='ca')


@pytest.mark.parametrize('users', ['CA_AgentR', 'CA_AdminR'])
def test_pki_ca_user_find_with_revoked_certs(ansible_module, users):
    """
    :Title: test pki ca-user-find command, when find user using a revoked cert CA_adminR
            and CA_AgentR certificate.
    :Description: Command should throws the excption : "PKIException: Unauthorized"
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults: Verify whether pki ca-user-find with revoked admin throws the "PKIException:
            Unauthorized".
    :Automated: Yes
    :CaseComponent: \-
    """

    user_find_cmd_out = ansible_module.pki(cli=pki_cmd,
                                           nssdb=constants.NSSDB,
                                           dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                           port=constants.CA_HTTP_PORT,
                                           certnick='"{}"'.format(users))
    for result in user_find_cmd_out.values():
        if result['rc'] == 0:
            assert "Number of entries returned 20" in result['stdout']
            log.error('Failed to ran: {}'.format(result['cmd']))
            pytest.fail("")
        else:
            error = "PKIException: Unauthorized"
            assert error in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))


@pytest.mark.parametrize('users', ['CA_AgentV', 'CA_AuditV'])
def test_pki_ca_user_find_with_valid_certs(ansible_module, users):
    """
    :Title: test pki ca-user-find command, find user using a valid CA_agentV and CA_AuditV cert
    :Description: Command should throws the excption : "ForbiddenException: Authorization Error"
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults:
        1. Verify whether pki ca-user-find with valid agent throws the
            "ForbiddenException: Authorization Error".
    :Automated: Yes
    :CaseComponent: \-
    """

    user_find_cmd_out = ansible_module.pki(cli=pki_cmd,
                                           nssdb=constants.NSSDB,
                                           dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                           port=constants.CA_HTTP_PORT,
                                           hostname=constants.MASTER_HOSTNAME,
                                           certnick='"{}"'.format(users))
    for result in user_find_cmd_out.values():
        if result['rc'] == 0:
            assert "Number of entries returned 20" in result['stdout']
            log.error('Failed to ran: {}'.format(result['cmd']))
            pytest.fail("")
        else:
            error = "ForbiddenException: Authorization Error"
            assert error in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))


@pytest.mark.parametrize('users', ['CA_AgentE', 'CA_AdminE'])
def test_pki_ca_user_find_with_expired_cert(ansible_module, users):
    """
    :Title: test pki ca-user-find command, when find user using a expired admin cert
            CA_adminE and Expired agent Cert CA_AgentE
    :Description: Command should throws the excption : "PKIException: Unauthorized"
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults: Verify whether pki ca-user-find with expired admin throws the
            "PKIException: Unauthorized".
    :Automated: Yes
    :CaseComponent: \-
    """

    user_find_cmd_out = ansible_module.pki(cli=pki_cmd,
                                           nssdb=constants.NSSDB,
                                           dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                           port=constants.CA_HTTP_PORT,
                                           hostname=constants.MASTER_HOSTNAME,
                                           certnick='"{}"'.format(users))
    for result in user_find_cmd_out.values():
        if result['rc'] == 0:
            assert "Number of entries returned 20" in result['stdout']
            log.error('Failed to ran: {}'.format(result['cmd']))
            pytest.fail("")
        else:
            assert "SEVERE: FATAL: SSL alert received: CERTIFICATE_EXPIRED\nIOException: " \
                   "SocketException cannot read on socket: Error reading from socket: " \
                   "(-12269) SSL peer rejected your certificate as expired." in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))


def test_pki_ca_user_find_with_valid_operator(ansible_module):
    """
    :Title: test pki ca-user-find command, when find user using a valid operator cert CA_operatorV
    :Description: Command should throws the excption : "ForbiddenException: Authorization Error"
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults:
        1. Verify whether pki ca-user-find with valid operator throws the
            "ForbiddenException: Authorization Error".
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'CA_OperatorV'
    fullName = 'CA OperatorV'
    group = 'Operator'
    subject = 'UID={},CN={}'.format(user, fullName)
    group_add = basic_pki_cmd + ' ca-group-add {} --description "Operator Group"'.format(group)

    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
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
                pytest.fail()

    user_del_out = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.CA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(user))
    for result in user_del_out.values():
        if result['rc'] == 0:
            log.error('Failed to run: {}'.format(result['cmd']))
            log.info(result['cmd'])
            pytest.fail('')
        else:
            error = "ForbiddenException: Authorization Error"
            assert error in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
    userop.remove_user(ansible_module, user)
    ansible_module.command(group_del + group)
    ansible_module.command(client_cert_del + '"{}"'.format(user))


def test_pki_ca_user_find_using_normal_user_cert(ansible_module):
    """
    :Title: test pki ca-user-find command, find a user using normal user certificate
    :Description: Command should throws the excption : "PKIException: Unauthorized"
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :ExpectedResults:
        1. Verify whether pki ca-user-find using a user cert should not find the users.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'tuser1{}'.format(str(random.randint(111, 999999)))
    full_name = "User {}".format(user)
    userop.add_user(ansible_module, 'add', userid=user, user_name=full_name)

    subject = 'UID={},CN={}'.format(user, full_name)

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
            else:
                pytest.fail("Failed to import certificate.")

    user_find_out = ansible_module.pki(cli=pki_cmd,
                                       nssdb=constants.NSSDB,
                                       dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                       port=constants.CA_HTTP_PORT,
                                       hostname=constants.MASTER_HOSTNAME,
                                       certnick='"{}"'.format(user))
    for result in user_find_out.values():
        if result['rc'] == 0:
            log.error('Failed to run: {}'.format(result['cmd']))
            log.info(result['cmd'])
            pytest.fail('')
        else:
            error = "ForbiddenException: Authorization Error"
            assert error in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
    userop.remove_user(ansible_module, user)
    ansible_module.command('pki -d {} -c {} client-cert-del '
                           '{}'.format(constants.NSSDB, constants.CLIENT_DIR_PASSWORD, user))


def test_pki_ca_user_find_with_filter(ansible_module):
    """
    :Title: Test pki ca-cert-find with filter
    :Description: Test pki ca-cert-find with filter
    :Requirement:  Certificate Authority Users
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Test pki ca-cert-find ca_audit
    :ExpectedResults:
        1. It should list all the certificates matching with that pattern.
    """
    user_find_out = ansible_module.pki(cli=pki_cmd,
                                       nssdb=constants.NSSDB,
                                       dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                       port=constants.CA_HTTP_PORT,
                                       hostname=constants.MASTER_HOSTNAME,
                                       certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                       extra_args='ca_admin')
    for result in user_find_out.values():
        if result['rc'] == 0:
            assert 'CA_AdminV' in result['stdout']
            assert 'CA_AdminE' in result['stdout']
            assert 'CA_AdminR' in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error('Failed to run: {}'.format(result['cmd']))
            pytest.fail('')
