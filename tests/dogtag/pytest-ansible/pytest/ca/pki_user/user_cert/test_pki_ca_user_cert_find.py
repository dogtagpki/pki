#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI CA-USER-CERT-FIND CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki user commands needs to be tested:
#   pki ca-user-cert-find
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
import re
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

pki_cmd = "ca-user-cert-find"
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
            'ca-group-del '.format(constants.NSSDB, constants.CLIENT_DIR_PASSWORD, constants.MASTER_HOSTNAME,
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
def test_pki_ca_user_cert_find_with_help(ansible_module, args):
    """
    :Title: Test pki ca-user-cert-find --help command
    :Description: Command should show pki ca-user-cert-find --help options and uses.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :CaseComponent: \-
    :Steps:
        1. Run pki ca-user-cert-find --help
        2. Run pki ca-user-cert-find
    :ExpectedResults:
        1. Verify whether pki ca-user-cert-find --help should show the options and uses messages.
        2. It will throw an error.
    :Automated: Yes
    :CaseComponent: \-
    """

    cer_del_help = 'pki {} {}'.format(pki_cmd, args)
    del_help_out = ansible_module.command(cer_del_help)
    for result in del_help_out.values():
        if result['rc'] == 0:
            assert "usage: {} <User ID> [OPTIONS...]".format(pki_cmd) in result['stdout']
            assert "--size <size>     Page size" in result['stdout']
            assert "--start <start>   Page start" in result['stdout']
            log.info('Successfully ran {}'.format(" ".join(result['cmd'])))
        elif args == '':
            assert 'No User ID specified' in result['stderr']
            log.info('Successfully ran {}'.format(" ".join(result['cmd'])))
        else:
            log.error('Failed to ran {}'.format(" ".join(result['cmd'])))
            pytest.fail()


def test_pki_ca_user_cert_find_certs_of_user(ansible_module):
    """
    :Title: Test pki ca-user-cert-find, find certs of user in CA with userID.
    :Description: Command should show pki ca-user-cert-find, find certs of user in CA with  userID it should
        shows the certificates which is added to user.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :steps:
        1. Add User
        2. Add certificate to user.
        3. Run pki ca-user-cert-find <userid>
    :ExpectedResults:
        1. Command should show no of certificates which are added in the user.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'testuser0'
    fullName = 'Test User0'
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
                                     extra_args='{}'.format(user))
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


def test_pki_ca_user_cert_find_with_multiple_pages_of_cert(ansible_module):
    """
    :Title: Test pki ca-user-cert-find CLI with userID - multiple pages of certs.
    :Description: Command should show pki ca-user-cert-find, find certs of user in CA with userID it should shows the
                 multiple certificates which is added to user.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add user.
        2. Add certificates to the user.
        3. Run pki ca-user-cert-find <userid>
    :ExpectedResults:
        1. Command should show no of certificates which are added in the user.
    :Automated: Yes
    :CaseComponent: \-
    """

    cert_id = None
    user = 'testuser1'
    fullName = 'Test User1'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    cert_ids = []
    subject = 'UID={},CN={}'.format(user, fullName)
    for algo in ['rsa', 'ecc']:
        if algo == 'rsa':
            cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                         request_type='pkcs10', algo='rsa',
                                                         keysize='2048', profile='caUserCert')
        elif algo == 'ecc':
            cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                         request_type='pkcs10', algo='ec',
                                                         curve='nistp521', profile='caECUserCert')
        cert_ids.append(cert_id)
        if cert_id:
            log.info("Generated certificate with cert ID: {}".format(cert_id))
            cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
            add_cert_to_user(ansible_module, user, subject, cert_id, cert_subject)
        else:
            log.error("Failed to generate certificate.")
            pytest.fail("")

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(user))
    for result in cmd_out.values():
        if result['rc'] == 0:
            for cert in cert_ids:
                cert_subject = "2;{};{};{}".format(int(cert, 16), CA_SUBJECT, subject)
                if cert_subject in result['stdout']:
                    assert 'Cert ID: {}'.format(cert_subject) in result['stdout']
                    assert 'Version: 2' in result['stdout']
                    assert 'Serial Number: {}'.format(cert_id) in result['stdout']
                    assert 'Issuer: {}'.format(CA_SUBJECT) in result['stdout']
                    assert 'Subject: {}'.format(subject) in result['stdout']
                    log.info("Found certificate entry for: {}".format(cert_subject))
                    log.info("Successfully run: \"{}\"".format(result['cmd']))
                else:
                    log.error("Failed to run: {}".format(result['cmd']))
                    pytest.fail()


def test_pki_ca_user_cert_find_when_user_does_not_exists(ansible_module):
    """
    :Title: Test pki ca-user-cert-find CLI with userID - when user does not exits.
    :Description: Command should show pki ca-user-cert-find CLI when user does not exits and throws an error.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-user-cert-find <user_non_exists>
    :ExpectedResults:
        1. Verify whether pki ca-user-cert-find throws the error when user does not exits.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = 'NOt_exits'
    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(user))
    for result in cmd_out.values():
        if result['rc'] == 0:

            assert 'Version: 2' in result['stdout']
            assert 'Issuer: {}'.format(CA_SUBJECT) in result['stdout']
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()

        else:
            error = "UserNotFoundException: User NOt_exits not found"
            assert error in result['stderr']
            log.info("Successfully run: {}".format(result['cmd']))


def test_pki_ca_user_cert_find_no_certs_added_to_user(ansible_module):
    """
    :Title: Test pki ca-user-cert-find CLI with userID - no certs added to user.
    :Description: Command should show pki ca-user-cert-find, find certs of user in CA with userID it should
                shows certs added to user if no certs added it should shows 0 entries.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add User.
        2. Do not add certificates to user.
        3. Run pki ca-user-cert-find <user>
    :ExpectedResults:
        1 .Command should show 0 entries if nocertificates are added to user.
    :Automated: Yes
    :CaseComponent: \-
    """

    user = 'testuser2'
    fullName = 'Test User2'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(user))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert '0 entries matched' in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()

    userop.remove_user(ansible_module, user)


@pytest.mark.parametrize('sizes', ['-1', '0', '1', '20', 'asdfa'])
def test_pki_ca_user_cert_find_with_different_sizes(ansible_module, sizes):
    """
    :Title: Test pki ca-user-cert-find CLI with --size 1.
    :Description: Command should show pki ca-user-cert-find, find certificate with size 1
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add User
        2. Add multiple certs to user.
        3. Run pki ca-user-cert-find <user> --size 1
        4. Run pki ca-user-cert-find <user> --size 0
        5. Run pki ca-user-cert-find <user> --size -1
        6. Run pki ca-user-cert-find <user> --size 20
        7. Run pki ca-user-cert-find <user> --size asdfa
    :ExpectedResults: 
        1. For size 1, it should show one entry
        2. For size 0, it should not show any entry.
        3. For size -1, it should not show any entry.
        4. For size 20, it should show all available entries till 20.
        5. For size asdfa. it should throw an exception.
    :Automated: Yes
    :CaseComponent: \-
    """

    user = 'testuser3'
    fullName = 'Test User3'
    certs = None
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    cert_ids = []
    subject = 'UID={},CN={}'.format(user, fullName)
    for algo in range(5):
        cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                     request_type='pkcs10', algo='ec',
                                                     curve='nistp521', profile='caECUserCert')
        cert_ids.append(cert_id)
        if cert_id:
            log.info("Generated certificate with cert ID: {}".format(cert_id))
            cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
            add_cert_to_user(ansible_module, user, subject, cert_id, cert_subject)
        else:
            log.error("Failed to generate certificate.")
            pytest.fail("")

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --size {}'.format(user, sizes))
    for result in cmd_out.values():
        if result['rc'] == 0:
            certs = re.findall('Serial Number: [\w].*', result['stdout'])
            if int(sizes) <= 0:
                assert 0 == len(certs)
            else:
                assert int(sizes) == len(certs)
            log.info("Successfully run: {}".format(result['cmd']))
        elif sizes == 'asdfa':
            assert 'NumberFormatException: For input string: "asdfa"' in result['stderr']
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()
    if sizes == '20':
        userop.remove_user(ansible_module, user)


@pytest.mark.parametrize('start', ['-1', '0', '2', '6980263829', 'asdfa'])
def test_pki_ca_user_cert_find_with_different_start_size(ansible_module, start):
    """
    :Title: Test pki ca-user-cert-find with different start sizes.
    :Description: Command should show pki ca-user-cert-find, find certs with different start size.
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add user
        2. Add certificate to the user
        3. Run pki ca-user-cert-find --size -1
        4. Run pki ca-user-cert-find --size 0
        5. Run pki ca-user-cert-find --size 2
        6. Run pki ca-user-cert-find --size 6980263829
        7. Run pki ca-user-cert-find --size asdfa
    :ExpectedResults:
        1. start -1, should return 19 entries
        2. start 0, should return 20 entries.
        3. start 2, should return entries till 20.
        4. start 6980263829, should return all entries
        5. start asdfa, should throw an Exception.
    :Automated: Yes
    :CaseComponent: \-
    """

    user = 'testuser4'
    fullName = 'Test user4'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    cert_ids = []
    subject = 'UID={},CN={}'.format(user, fullName)
    for algo in range(5):
        cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                     request_type='pkcs10', algo='ec',
                                                     curve='nistp521', profile='caECUserCert')
        cert_ids.append(cert_id)
        if cert_id:
            log.info("Generated certificate with cert ID: {}".format(cert_id))
            cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
            add_cert_to_user(ansible_module, user, subject, cert_id, cert_subject)
        else:
            log.error("Failed to generate certificate.")
            pytest.fail("")

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --start {}'.format(user, start))
    for result in cmd_out.values():
        if result['rc'] == 0:
            certs = re.findall('Serial Number: [\w].*', result['stdout'])
            if int(start) <= 0:
                assert 0 <= len(certs)
            else:
                assert int(start) <= len(certs)
            log.info("Successfully run: {}".format(result['cmd']))
        elif start in ['6980263829', 'asdfa']:
            assert 'NumberFormatException: For input string: "{}"'.format(start) in result['stderr']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()
    if start.isdigit() and int(start) >= 20:
        userop.remove_user(ansible_module, user)


@pytest.mark.parametrize('start', ['0', '1', '-1', '20'])
@pytest.mark.parametrize('size', ['0', '1', '-1', '20'])
def test_pki_ca_user_cert_find_with_size_and_start_1(ansible_module, start, size):
    """
    :Title: Test pki ca-user-cert-find CLI with userID --start=0 --size=0
    :Description: Command should show pki ca-user-cert-find CLI with userID --start=0 --size=0
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-user-cert-find <user> --size 0 --start 0
        2. Run pki ca-user-cert-find <user> --size 0 --start 1
        3. Run pki ca-user-cert-find <user> --size 0 --start -1
        4. Run pki ca-user-cert-find <user> --size 0 --start 20
        5. Run pki ca-user-cert-find <user> --size 1 --start 0
        6. Run pki ca-user-cert-find <user> --size 1 --start 1
        7. Run pki ca-user-cert-find <user> --size 1 --start -1
        8. Run pki ca-user-cert-find <user> --size 1 --start 20
        9. Run pki ca-user-cert-find <user> --size -1 --start 0
        10. Run pki ca-user-cert-find <user> --size -1 --start 1
        11. Run pki ca-user-cert-find <user> --size -1 --start -1
        12. Run pki ca-user-cert-find <user> --size -1 --start 20
        13. Run pki ca-user-cert-find <user> --size 20 --start 0
        14. Run pki ca-user-cert-find <user> --size 20 --start 1
        15. Run pki ca-user-cert-find <user> --size 20 --start -1
        16. Run pki ca-user-cert-find <user> --size 20 --start 20
    :ExpectedResults:
        1. Verify whether pki ca-user-cert-find shows certificate lists.
    :Automated: Yes
    :CaseComponent: \-
    """

    user = 'testuser5'
    fullName = 'Test User5'
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    cert_ids = []
    subject = 'UID={},CN={}'.format(user, fullName)
    for algo in range(5):
        cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                     request_type='pkcs10', algo='ec',
                                                     curve='nistp521', profile='caECUserCert')
        cert_ids.append(cert_id)
        if cert_id:
            log.info("Generated certificate with cert ID: {}".format(cert_id))
            cert_subject = "2;{};{};{}".format(int(cert_id, 16), CA_SUBJECT, subject)
            add_cert_to_user(ansible_module, user, subject, cert_id, cert_subject)
        else:
            log.error("Failed to generate certificate.")
            pytest.fail("")

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --size {} --start {}'.format(user, size, start))
    for result in cmd_out.values():
        if result['rc'] == 0:
            certs = re.findall('Serial Number: [\w].*', result['stdout'])
            if int(start) <= 0 or int(size) <= 0:
                assert 0 <= len(certs)
            else:
                if start == '20' and size == '20':
                    assert 'entries matched' in result['stdout']
                    assert 'Number of entries returned' in result['stdout']
                else:
                    assert int(size) == len(certs)
            log.info("Successfully run: {}".format(result['cmd']))
        elif start == 'asdfa':
            assert 'NumberFormatException: For input string: "asdfa"' in result['stderr']
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()
    if int(size) == 20 and int(start) == 20:
        userop.remove_user(ansible_module, user)


@pytest.mark.parametrize("users", ['CA_AgentV', 'CA_AuditV'])
def test_pki_ca_user_cert_find_with_valid_certs(ansible_module, users):
    """
    :Title: Test pki ca-user-cert-find CLI with user as CA_AgentV, CA_AuditV
    :Description: Command should show pki ca-user-cert-find CLI with user as CA_AgentV, CA_AuditV
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Run pki -n CA_AgentV ca-user-cert-find <admin_user>
        2. Run pki -n CA_AuditV ca-user-cert-find <admin_user>
    :ExpectedResults:
        1. Verify whether pki ca-user-cert-find throws error when user is CA_AgentV.
        2. Verify whether pki ca-user-cert-find throws error when user is CA_AuditV.
    :Automated: Yes
    :CaseComponent: \-
    """
    user = constants.CA_ADMIN_USERNAME
    caadmin_sub = 'CN=PKI Administrator,E=caadmin@example.com,' \
                  'OU={},O={}'.format(constants.CA_INSTANCE_NAME, constants.CA_SECURITY_DOMAIN_NAME)
    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 hostname=constants.MASTER_HOSTNAME,
                                 port=constants.CA_HTTP_PORT,
                                 certnick='"{}"'.format(users),
                                 extra_args='{}'.format(user))
    for res in cmd_out.values():
        if res['rc'] == 0:
            assert 'Version: 2' in res['stdout']
            assert 'Issuer: {}'.format(CA_SUBJECT) in res['stdout']
            assert 'Subject: {}'.format(caadmin_sub) in res['stdout']
            log.info('Failed to run: {}'.format(res['cmd']))
            pytest.fail('')
        else:
            log.info('Successfully ran: {}'.format(res['cmd']))
            error = "ForbiddenException: Authorization Error"
            assert error in res['stderr']


@pytest.mark.parametrize("users", ['CA_AdminE', 'CA_AgentE', 'CA_AuditE'])
def test_pki_ca_user_cert_find_with_expired_user_certs(ansible_module, users):
    """
    :Title: Test pki ca-user-cert-find CLI with user as CA_AdminE, CA_AgnetE, CA_AuditE
    :Description: Command should show pki ca-user-cert-find CLI with user as CA_AgentE, CA_AuditE and CA_AdminE
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Run pki -n CA_AdminE ca-user-cert-find <admin_user>
        2. Run pki -n CA_AgentE ca-user-cert-find <admin_user>
        3. Run pki -n CA_AuditE ca-user-cert-find <admin_user>
    :ExpectedResults:
        1. Verify whether pki ca-user-cert-find throws error when user is CA_AdminE.
        2. Verify whether pki ca-user-cert-find throws error when user is CA_AgentE.
        3. Verify whether pki ca-user-cert-find throws error when user is CA_AuditE.
    :Automated: Yes
    :CaseComponent: \-
    """

    user = constants.CA_ADMIN_USERNAME
    caadmin_sub = 'CN=PKI Administrator,E=caadmin@example.com,' \
                  'OU={},O={}'.format(constants.CA_INSTANCE_NAME, constants.CA_SECURITY_DOMAIN_NAME)
    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 hostname=constants.MASTER_HOSTNAME,
                                 port=constants.CA_HTTP_PORT,
                                 certnick='"{}"'.format(users),
                                 extra_args='{}'.format(user))
    for res in cmd_out.values():
        if res['rc'] == 0:
            assert 'Version: 2' in res['stdout']
            assert 'Issuer: {}'.format(CA_SUBJECT) in res['stdout']
            assert 'Subject: {}'.format(caadmin_sub) in res['stdout']
            log.error('Failed to run: {}'.format(res['cmd']))
            pytest.fail('')
        else:
            assert "SEVERE: FATAL: SSL alert received: CERTIFICATE_EXPIRED\nIOException: " \
                   "SocketException cannot read on socket: Error reading from socket: " \
                   "(-12269) SSL peer rejected your certificate as expired." in res['stderr']
            log.info('Successfully ran: {}'.format(res['cmd']))
            # Keeping error assertions minimum would reduce chances of failure if message changes in future.
            error = 'CERTIFICATE_EXPIRED'
            # if 'CERTIFICATE_EXPIRED' in res['stderr']:
            #     error = "FATAL: SSL alert received: CERTIFICATE_EXPIRED\n" \
            #             "IOException: SocketException cannot write on socket"
            # else:
            #     error = "IOException: SocketException cannot write on socket"
            assert error in res['stderr']


@pytest.mark.parametrize("users", ['CA_AdminR', 'CA_AgentR', 'CA_AuditR'])
def test_pki_ca_user_cert_find_with_revoked_certs(ansible_module, users):
    """
    :Title: Test pki ca-user-cert-find CLI when user as CA_AdminR, CA_AgentR, CA_AuditR
    :Description: Command should show pki ca-user-cert-find CLI when user as CA_AdminR, CA_AgentR, CA_AuditR
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Run pki -n CA_AdminR ca-user-cert-find <admin_user>
        2. Run pki -n CA_AgentR ca-user-cert-find <admin_user>
        3. Run pki -n CA_AuditR ca-user-cert-find <admin_user>
    :ExpectedResults:
        1. Verify whether pki ca-user-cert-find throws error when user is CA_AdminR.
        2. Verify whether pki ca-user-cert-find throws error when user is CA_AgentR.
        3. Verify whether pki ca-user-cert-find throws error when user is CA_AuditR.
    :Automated: Yes
    :CaseComponent: \-
    """

    user = constants.CA_ADMIN_USERNAME
    caadmin_sub = 'CN=PKI Administrator,E=caadmin@example.com,' \
                  'OU={},O={}'.format(constants.CA_INSTANCE_NAME, constants.CA_SECURITY_DOMAIN_NAME)
    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 hostname=constants.MASTER_HOSTNAME,
                                 port=constants.CA_HTTP_PORT,
                                 certnick='"{}"'.format(users),
                                 extra_args='{}'.format(user))
    for res in cmd_out.values():
        if res['rc'] == 0:
            assert 'Version: 2' in res['stdout']
            assert 'Issuer: {}'.format(CA_SUBJECT) in res['stdout']
            assert 'Subject: {}'.format(caadmin_sub) in res['stdout']
            log.error('Failed to run: {}'.format(res['cmd']))
            pytest.fail('')
        else:
            log.info('Successfully ran: {}'.format(res['cmd']))
            error = "PKIException: Unauthorized"
            assert error in res['stderr']


def test_pki_ca_user_cert_find_with_ca_operatorv(ansible_module):
    """
    :Title: pki ca-user-cert-find CLI when user as a CA_OperatorV
    :Description: Command should show pki ca-user-cert-find CLI when user as CA_OperatorV
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add Operator group.
        2. Add user CA_OperatorV and add it to Operator group.
        3. Add new user.
        4. Issue certificate to both users.
        5. Import CA_OperatorV certificate to client db.
        6. Run pki -n CA_OperatorV ca-user-cert-find <new_user>
    :ExpectedResults:
        1. Verify whether pki ca-user-cert-find throws error when user is CA_OperatorV.
    :Automated: Yes
    :CaseComponent: \-
    """

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
            log.info('Failed to run: {}'.format(result['cmd']))
            pytest.fail('Failed to ran: {}'.format(result['cmd']))
        else:
            error = "ForbiddenException: Authorization Error"
            assert error in result['stderr']
            log.info('Successfully ran {}.'.format(result['cmd']))
    userop.remove_user(ansible_module, user)
    userop.remove_user(ansible_module, t_user)
    ansible_module.command(group_del + group)
    ansible_module.command(client_cert_del + '"{}"'.format(user))


def test_pki_ca_user_cert_find_user_not_associated_with_any_role(ansible_module):
    """
    :Title: Test pki ca-user-cert-find CLi with user who is not associated with any role
    :Description: Command should show pki ca-user-cert-find CLI when user who is not associated with any role
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Add user, Issue certificate to the user.
        2. Import certificate to the client db
        3. Run pki -n <new_user> ca-user-cert-find <user>
    :ExpectedResults:
        1.  Verify whether pki ca-user-cert-find throws error when user is not associated with any role user.
    :Automated: Yes
    :CaseComponent: \-
    """

    user = 'testuser4'
    fullName = 'Test User 4'
    subject = 'UID={},CN={}'.format(user, fullName)
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    cert_subject = None
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='ec',
                                                 curve='nistp521', profile='caECUserCert')
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
    else:
        log.error("Failed to generate certificate.")
        pytest.fail("")

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(user),
                                 extra_args='{}'.format(user))

    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Cert ID: {}'.format(cert_subject) in result['stdout']
            assert 'Version: 2' in result['stdout']
            assert 'Serial Number: {}'.format(cert_id) in result['stdout']
            assert 'Issuer: {}'.format(CA_SUBJECT) in result['stdout']
            assert 'Subject: {}'.format(subject) in result['stdout']
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()
        else:
            error = "ForbiddenException: Authorization Error"
            assert error in result['stderr']
            log.info('Successfully ran {}.'.format(result['cmd']))

    userop.remove_user(ansible_module, user)
    ansible_module.command('pki -d {} -c {} client-cert-del '
                           '{}'.format(constants.NSSDB, constants.CLIENT_DIR_PASSWORD, user))


def test_ca_cli_user_cert_find_without_userid(ansible_module):
    """
    :Title: Test pki ca-user-cert-find CLI without userID
    :Description: Command should show pki ca-user-cert-find CLI without userID
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-user-cert-find
    :ExpectedResults:
        1. Verify whether pki ca-user-cert-find throws error when userID is not specified
    :Automated: Yes
    :CaseComponent: \-
    """

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK))

    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Cert ID:' in result['stdout']
            assert 'Version: 2' in result['stdout']
            assert 'Serial Number:' in result['stdout']
            assert 'Issuer:' in result['stdout']
            assert 'Subject:' in result['stdout']
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()
        else:
            error = "No User ID specified."
            assert error in result['stderr']
            log.info("Successfully run: {}".format(result['cmd']))


def test_pki_ca_user_cert_find_without_userid_with_params(ansible_module):
    """
    :Title: Test pki ca-user-cert-find CLI missing userID with --size and --start options
    :Description: Command should show pki ca-user-cert-find CLI missing userID with --size and --start options
    :Requirement: Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-user-cert-find --size 20 --start 0
    :ExpectedResults:
        1. Verify whether pki ca-user-cert-find throws error when userID is not specified
    :Automated: Yes
    :CaseComponent: \-
    """
    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args=" --start 20 --size 0")

    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Cert ID:' in result['stdout']
            assert 'Version: 2' in result['stdout']
            assert 'Serial Number:' in result['stdout']
            assert 'Issuer:' in result['stdout']
            assert 'Subject:' in result['stdout']
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()
        else:
            error = "No User ID specified."
            assert error in result['stderr']
            log.info("Successfully run: {}".format(result['cmd']))
