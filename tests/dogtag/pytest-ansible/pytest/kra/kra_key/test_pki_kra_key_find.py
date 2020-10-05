#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI KRA KEY CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following kra-key-find cli commands needs to be tested:
#   pki kra-key-find
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

import pytest

from pki.testlib.common import utils

if os.path.isfile('/tmp/test_dir/constants.py'):
    sys.path.append('/tmp/test_dir')
    import constants

userop = utils.UserOperations(nssdb=constants.NSSDB)
log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
TOPOLOGY = constants.CA_INSTANCE_NAME.split("-")[1]
key_library = utils.pki_key_library()

pki_cmd = 'kra-key-find'
if TOPOLOGY != '01':
    CA_SUBJECT = 'CN=CA Signing Certificate,OU={},O={}'.format(constants.CA_INSTANCE_NAME,
                                                               constants.CA_SECURITY_DOMAIN_NAME)
else:
    CA_SUBJECT = 'CN=CA Signing Certificate,OU={},O={}'.format('pki-tomcat',
                                                               constants.CA_SECURITY_DOMAIN_NAME)

basic_pki_cmd_ca = 'pki -d {} -c {} -p {} -n "{}" '.format(constants.NSSDB,
                                                           constants.CLIENT_DIR_PASSWORD,
                                                           constants.CA_HTTPS_PORT,
                                                           constants.CA_ADMIN_NICK)

group_del = 'pki -d {} -c {} -p {} -n "{}" ' \
            'ca-group-del '.format(constants.NSSDB, constants.CLIENT_DIR_PASSWORD,
                                   constants.CA_HTTPS_PORT, constants.CA_ADMIN_NICK)

client_cert_del = 'pki -d {} -c {} client-cert-del '.format(constants.NSSDB,
                                                            constants.CLIENT_DIR_PASSWORD)


@pytest.mark.parametrize('subcmd', ['', '--help'])
def test_pki_kra_key_find_help(ansible_module, subcmd):
    """
    :Title: Test pki kra-key-find with '' and '--help'
    :Test: Test pki kra-key-find command with '' and '--help'
    :Description:
        This command will test the pki kra-key-find with '' and '--help' option,
        for '' option it is expected to show the keys form the database, and
        for '--help' it should show the help message.
    :Requirement: pki kra-key-find
    :CaseComponent: \-
    :Type:
    :Steps:
        1. pki kra-key-find
        2. pki kra-key-find --help
    :ExpectedResults:
        1. It should shows the kra keys form the database
        2. --help option should shows the help message.
    """
    output = ansible_module.pki(cli=pki_cmd,
                                nssdb=constants.NSSDB,
                                dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                port=constants.KRA_HTTP_PORT,
                                hostname=constants.MASTER_HOSTNAME,
                                certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                extra_args=subcmd)
    for result in output.values():
        if subcmd == '--help':
            assert result['rc'] == 0
            assert 'usage: kra-key-find [OPTIONS...]' in result['stdout']
            assert '--clientKeyID <client key ID>   Unique client key identifier' in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))
        elif subcmd == '':
            assert 'Number of entries returned' in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))


def test_pki_kra_key_find_with_valid_clientid(ansible_module):
    """
    :Title: Test pki kra-key-find with valid id passed to '--clientKeyID'
    :Test: Test pki kra-key-find with '--clientKeyID'
    :Description:
        This command will test the pki kra-key-find with '--clientKeyID' option,
        it is expected to show the key associated with the client ID's value.
    :Requirement: pki kra-key-find
    :CaseComponent: \-
    :Steps:
        1. pki kra-key-find --clientKeyID <client key ID>
    :ExpectedResults:
        1. It should show the kra key with the associated client key ID.
    """
    clientid_random = 'testuser21021_{}'.format(random.randint(1111, 99999999))
    key_id = key_library.generate_key(ansible_module, algo='RSA',
                                      key_size='2048', usages='wrap,unwrap',
                                      client_key_id=clientid_random)
    output = ansible_module.pki(cli=pki_cmd,
                                nssdb=constants.NSSDB,
                                dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                port=constants.KRA_HTTP_PORT,
                                hostname=constants.MASTER_HOSTNAME,
                                certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                extra_args='--clientKeyID {}'.format(clientid_random))
    for result in output.values():
        if result['rc'] == 0:
            assert "Key ID: {}".format(key_id['key_id']) in result['stdout']
            assert "Client Key ID: {}".format(clientid_random) in result['stdout']
            assert "Status: active" in result['stdout']
            assert "Algorithm: RSA" in result['stdout']
            assert "Owner: {}".format(constants.KRA_ADMIN_USERNAME) in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


@pytest.mark.parametrize('value', ['valid', 'junk', ''])
def test_pki_kra_key_find_with_different_value_passed_to_clientid(ansible_module, value):
    """
    :Title: Test pki kra-key-find with different value passed to '--clientKeyID'
    :Test: Test pki kra-key-find with different value passed to '--clientKeyID'
    :Description:
        This command will test the pki kra-key-find with junk/random '--clientKeyID' options,
        it is expected to show the number of entries as 0 .
    :Requirement: pki kra-key-find
    :CaseComponent: \-
    :Steps:
        1. pki kra-key-find --clientKeyID <junk>
        2. pki kra-key-find --clientKeyID <random>
    :ExpectedResults:
        1. junk/random option in results should show the number of entries as 0 .
    """
    clientid = ''
    if value == 'valid':
        clientid = 'testuser21022_{}'.format(random.randint(1111, 99999999))
        key_id = key_library.generate_key(ansible_module, algo='RSA',
                                          key_size='2048', usages='wrap,unwrap',
                                          client_key_id=clientid)
    elif value == 'junk':
        clientid = os.popen("openssl rand -base64 50 |  perl -p -e 's/\n//'").read()
    elif value == '':
        clientid = ''
    output = ansible_module.pki(cli=pki_cmd,
                                nssdb=constants.NSSDB,
                                dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                port=constants.KRA_HTTP_PORT,
                                hostname=constants.MASTER_HOSTNAME,
                                certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                extra_args='--clientKeyID {}'.format(clientid))
    for result in output.values():
        if value == 'valid':
            assert result['rc'] == 0
            assert "Key ID: {}".format(key_id['key_id']) in result['stdout']
            assert "Client Key ID: {}".format(clientid) in result['stdout']
            assert "Status: active" in result['stdout']
            assert "Algorithm: RSA" in result['stdout']
            assert "Owner: {}".format(constants.KRA_ADMIN_USERNAME) in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))
        elif value == 'junk':
            assert 'Number of entries returned 0' in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))
        elif value == '':
            assert 'MissingArgumentException: Missing argument for option: clientKeyID' in result['stderr']
            log.info("Successfully run : {}".format(result['cmd']))


@pytest.mark.parametrize('value', ['5', 'valid', '-128', 'junk', '1234567890123', ''])
def test_pki_kra_key_find_with_max_result_value(ansible_module, value):
    """
    :Title: Test pki kra-key-find with valid value passed to '--maxResults'
    :Test: Test pki kra-key-find with '--maxResults'
    :Description:
        This command will test the pki kra-key-find with '--maxResults' option,
        it is expected to show the key associated with the maxResult's value.
    :Requirement: pki kra-key-find
    :CaseComponent: \-
    :Steps:
        1. pki kra-key-find --maxResults <max results>
    :ExpectedResults:
        1. It should result in number of entries returned as 5 .
    """
    max = ''
    if value == 'valid':
        max = '10'
    elif value == 'junk':
        max = os.popen("openssl rand -base64 50 |  perl -p -e 's/\n//'").read()
    elif value == '':
        max = ''
    else:
        max = value
    if value in ['valid', '5', '-128']:
        for x in range(1, 6):
            user = 'testuser21023_{}'.format(random.randint(1111, 99999999))
            key_id = key_library.generate_key(ansible_module, algo='RSA',
                                              key_size='2048', usages='wrap,unwrap',
                                              client_key_id=user)
            log.info("Generated key: \n Key Serial: {} \n Key ID: {}".format(key_id['key_id'], user))
    output = ansible_module.pki(cli=pki_cmd,
                                nssdb=constants.NSSDB,
                                dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                port=constants.KRA_HTTP_PORT,
                                hostname=constants.MASTER_HOSTNAME,
                                certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                extra_args='--maxResults {}'.format(max))
    for result in output.values():
        if value in ['']:
            assert result['rc'] >= 1
            assert 'MissingArgumentException: Missing argument for option: maxResults' in result['stderr']
            log.info("Successfully run : {}".format(result['cmd']))
        elif value in ['junk', '1234567890123']:
            assert 'NumberFormatException: For input string: "{}"'.format(max) in result['stderr']
            log.info("Successfully run : {}".format(result['cmd']))
        elif value in ['5', 'valid', '-128']:
            if value == '-128':
                max = 20
            assert 'Number of entries returned {}'.format(max) in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))


@pytest.mark.parametrize('value', ['5', 'valid', 'junk', '1234567890123', '-128', ''])
def test_pki_kra_key_find_with_size_value(ansible_module, value):
    """
    :Title: Test pki kra-key-find with valid value passed to '--size'
    :Test: Test pki kra-key-find with '--size'
    :Description:
        This command will test the pki kra-key-find with '--size' option,
        it is expected to show the key associated with the size's value.
    :Requirement: pki kra-key-find
    :CaseComponent: \-
    :Steps:
        1. pki kra-key-find --size <size>
    :ExpectedResults:
        1. It should result in number of entries returned as 5 .
    """
    size = ''
    if value == 'valid':
        size = '10'
    elif value == 'junk':
        size = os.popen("openssl rand -base64 50 |  perl -p -e 's/\n//'").read()
    elif value == '':
        size = ''
    output = ansible_module.pki(cli=pki_cmd,
                                nssdb=constants.NSSDB,
                                dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                port=constants.KRA_HTTP_PORT,
                                hostname=constants.MASTER_HOSTNAME,
                                certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                extra_args='--size {}'.format(size))
    for result in output.values():
        if max in ['', 'junk', '1234567890123', '-128']:
            assert result['rc'] >= 1
            assert 'NumberFormatException: For input string: ' + value in result['stderr']
            log.info("Successfully run : {}".format(result['cmd']))
        elif max in ['5', 'valid']:
            assert result['rc'] == 0
            assert 'Number of entries returned {}'.format(max) in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))


@pytest.mark.parametrize('value', ['active', 'inactive', 'junk', ''])
def test_pki_kra_key_find_with_different_key_status(ansible_module, value):
    """
    :Title: Test pki kra-key-find with active value passed to '--status'
    :Description:
        This command will test the pki kra-key-find with active value passed to --status and
        1000 value passed to --maxResults and --size.
    :Requirement: pki kra-key-find
    :CaseComponent: \-
    :Steps:
        1. pki kra-key-find --status active --maxResults 1000 --size 1000
    :ExpectedResults:
        1. The status of the keys listed should be active.
    """
    if value == 'junk':
        status = os.popen("openssl rand -base64 50 |  perl -p -e 's/\n//'").read()
    else:
        status = value
    clientid = 'testuser21024_{}'.format(random.randint(1111, 99999999))
    key_id = key_library.generate_key(ansible_module, algo='RSA',
                                      key_size='2048', usages='wrap,unwrap',
                                      client_key_id=clientid)
    log.info("Generated key: \n Key Serial: {} \n Key ID: {}".format(key_id['key_id'], clientid))
    if status == 'inactive':
        inactive = key_library.modify_key_status(ansible_module, key_id['key_id'], status='inactive')
        assert inactive is True
        log.info("Key set to inactive.")

    output = ansible_module.pki(cli=pki_cmd,
                                nssdb=constants.NSSDB,
                                dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                port=constants.KRA_HTTP_PORT,
                                hostname=constants.MASTER_HOSTNAME,
                                certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                extra_args='--status {} --size 1000 --maxResults 1000'.format(status))
    for result in output.values():
        if status in ['active', 'inactive']:
            assert result['rc'] == 0
            assert "Key ID: {}".format(key_id['key_id']) in result['stdout']
            assert "Client Key ID: {}".format(clientid) in result['stdout']
            assert "Status: {}".format(status) in result['stdout']
            assert "Algorithm: RSA" in result['stdout']
            assert "Owner: {}".format(constants.KRA_ADMIN_USERNAME) in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))
        elif value == 'junk':
            assert '0 key(s) matched' in result['stdout']
            assert 'Number of entries returned 0' in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))
        elif value in ['']:
            assert 'MissingArgumentException: Missing argument for option: status' in result['stderr']
            log.info("Successfully run : {}".format(result['cmd']))


@pytest.mark.parametrize('start', ['5', '0', '-1', '123456789098', 'abcdefgh', ''])
def test_pki_kra_key_find_with_key_start_from_different_values(ansible_module, start):
    """
    :Title: Test pki kra-key-find with positive and negative value passed to '--start'
    :Description:
        This command will test the pki kra-key-find with positive and negative value passed to --start
    :Requirement: pki kra-key-find
    :CaseComponent: \-
    :Steps:
        1. pki kra-key-find --start 5
        2. pki kra-key-find --start -128
    :ExpectedResults:
        1. Positive value should result in listing keys starting from Key ID:0x6.
        2. Negative value should result in Number of entries returned 0.
    """
    output = ansible_module.pki(cli=pki_cmd,
                                nssdb=constants.NSSDB,
                                dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                port=constants.KRA_HTTP_PORT,
                                hostname=constants.MASTER_HOSTNAME,
                                certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                extra_args='--start {}'.format(start))
    for result in output.values():
        if start in ['5', '0']:
            assert result['rc'] == 0
            assert "Key ID:" in result['stdout']
            assert "Client Key ID: " in result['stdout']
            assert "Status:" in result['stdout']
            assert "Algorithm: RSA" in result['stdout']
            assert "Owner: {}".format(constants.KRA_ADMIN_USERNAME) in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))
        elif start == '-1':
            assert "PKIException: Internal Server Error" in result['stderr']
        elif start in ['123456789098', 'abcdefgh']:
            assert 'NumberFormatException: For input string:' in result['stderr']
        elif start in ['']:
            assert 'MissingArgumentException: Missing argument for option: start' in result['stderr']
            log.info("Successfully run : {}".format(result['cmd']))


@pytest.mark.parametrize('max,size', [('105', '105')])
def test_pki_kra_key_find_with_maxresult_and_size_value(ansible_module, max, size):
    """
    :Title: Test pki kra-key-find with maxResults and size values.
    :Description: Test pki kra-key-find with maxResults and size values.
    :Requirement: pki kra-key-find
    :CaseComponent: \-
    :Steps:
        1. pki kra-key-find --maxResults 105 --size 105
    :ExpectedResults:
        1. When 105 as values are passed, it should return result as in Number of entries returned 105.
    """
    for x in range(1, 105):
        user = 'testuser21025_{}'.format(random.randint(1111, 99999999))
        key_library.generate_key(ansible_module, algo='RSA',
                                 key_size='2048', usages='wrap,unwrap',
                                 client_key_id=user)
    output = ansible_module.pki(cli=pki_cmd,
                                nssdb=constants.NSSDB,
                                dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                port=constants.KRA_HTTP_PORT,
                                hostname=constants.MASTER_HOSTNAME,
                                certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                extra_args='--maxResults {} --size {}'.format(max, size))
    for result in output.values():
        if result['rc'] == 0:
            assert "Key ID:" in result['stdout']
            assert "Client Key ID: " in result['stdout']
            assert "Status:" in result['stdout']
            assert "Algorithm: RSA" in result['stdout']
            assert "Owner: {}".format(constants.KRA_ADMIN_USERNAME) in result['stdout']
            assert 'Number of entries returned {}'.format(size) in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


@pytest.mark.parametrize('maxTime', ['10', 'abc', ''])
def test_pki_kra_key_find_with_maxtime_value(ansible_module, maxTime):
    """
    :Title: Test pki kra-key-find with size and maxTime values are passed.
    :Description: This command will test the pki kra-key-find with different value passed to
                --size and --maxTime respectively.
    :Requirement: pki kra-key-find
    :CaseComponent: \-
    :Type:
    :Steps:
        1. pki kra-key-find --size 10 --maxTime 5
        2. pki kra-key-find --size 10 --maxTime <junk>
    :ExpectedResults:
        1. When value are passed, it should return result as in Number of entries returned 10.
        2. When junk value is passed with maxTime, it should result in NumberFormatException.
    """
    output = ansible_module.pki(cli=pki_cmd,
                                nssdb=constants.NSSDB,
                                dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                port=constants.KRA_HTTP_PORT,
                                hostname=constants.MASTER_HOSTNAME,
                                certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                extra_args='--maxTime {} --size 10'.format(maxTime))
    for result in output.values():
        if maxTime == '5':
            assert result['rc'] == 0
            assert "Key ID:" in result['stdout']
            assert "Client Key ID:" in result['stdout']
            assert "Status:" in result['stdout']
            assert "Algorithm:" in result['stdout']
            assert "Size:" in result['stdout']
            assert "Owner:" in result['stdout']
            assert "Number of entries returned 10" in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        elif maxTime == 'abc':
            assert 'NumberFormatException: For input string: "abc"' in result['stderr']
            log.info("Successfully run: {}".format(result['cmd']))
        elif maxTime == '':
            assert "MissingArgumentException: Missing argument for option: maxTime" in result['stderr']
            log.info("Successfully run: {}".format(result['cmd']))


@pytest.mark.parametrize('certnick', ['KRA_AdminV', 'KRA_AuditV', 'KRA_AgentV'])
def test_pki_kra_key_find_with_different_valid_certs(ansible_module, certnick):
    """
    :Title: Test pki kra-key-find with different valid certificates passed.
    :Description: Test pki kra-key-find with different valid certificates passed.
    :Requirement: pki kra-key-find
    :CaseComponent: \-
    :Steps:
        1. pki -d <> -c <> -n KRA_AdminV -p <> kra-key-find.
        2. pki -d <> -c <> -n KRA_AgentV -p <> kra-key-find.
        3. pki -d <> -c <> -n KRA_AuditV -p <> kra-key-find.
    :ExpectedResults:
        1. It show throw Authorization error.
        2. It should return the entries of the keys.
        3. It show throw Authorization error.
    """
    output = ansible_module.pki(cli=pki_cmd,
                                nssdb=constants.NSSDB,
                                dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                port=constants.KRA_HTTP_PORT,
                                hostname=constants.MASTER_HOSTNAME,
                                certnick='"{}"'.format(certnick))
    for result in output.values():
        if certnick != 'KRA_AgentV':
            if result['rc'] >= 255:
                assert " " in result['stderr']
                log.info("Successfully run : {}".format(result['cmd']))
            else:
                log.error("Failed to run :  {}".format(result['cmd']))
                log.info(result['stdout'])
                log.error(result['stderr'])
                pytest.fail()
        else:
            assert 'Number of entries returned 20' in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))


@pytest.mark.parametrize('certnick', ['KRA_AdminR', 'KRA_AuditR', 'KRA_AgentR'])
def test_pki_kra_key_find_with_different_revoked_certs(ansible_module, certnick):
    """
    :Title: Test pki kra-key-find with different revoked certificates passed.
    :Description: This pki kra-key-find with different revoked certificates passed
    :Requirement: pki kra-key-find
    :CaseComponent: \-
    :Steps:
        1. pki -d <> -c <> -n KRA_AdminR -p <> kra-key-find.
        2. pki -d <> -c <> -n KRA_AgentR -p <> kra-key-find.
        3. pki -d <> -c <> -n KRA_AuditR -p <> kra-key-find.
    :ExpectedResults:
        1.
    """
    output = ansible_module.pki(cli=pki_cmd,
                                nssdb=constants.NSSDB,
                                dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                port=constants.KRA_HTTP_PORT,
                                hostname=constants.MASTER_HOSTNAME,
                                certnick='"{}"'.format(certnick))
    for result in output.values():
        if result['rc'] >= 1:
            assert 'FATAL: SSL alert received: CERTIFICATE_REVOKED' in result['stderr']
            log.info('Successfully run : {}'.format(result['cmd']))
        else:
            log.error("Failed to run :  {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


@pytest.mark.parametrize('certnick', ['KRA_AdminE', 'KRA_AuditE', 'KRA_AgentE'])
def test_pki_kra_key_find_with_different_expired_certs(ansible_module, certnick):
    """
    :Title: Test pki kra-key-find with different expired certificates passed.
    :Description: Test pki kra-key-find with different expired certificates passed.
    :Requirement: pki kra-key-find
    :CaseComponent: \-
    :Steps:
        1. pki -d <database_dir> -c <password> -n KRA_AdminV -p <port> kra-key-find.
        2. pki -d <database_dir> -c <password> -n KRA_AgentV -p <port> kra-key-find.
        3. pki -d <database_dir> -c <password> -n KRA_AuditV -p <port> kra-key-find.
    :ExpectedResults:
        1.
    """
    output = ansible_module.pki(cli=pki_cmd,
                                nssdb=constants.NSSDB,
                                dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                port=constants.KRA_HTTP_PORT,
                                hostname=constants.MASTER_HOSTNAME,
                                certnick='"{}"'.format(certnick))
    for result in output.values():
        if result['rc'] >= 1:
            if 'CERTIFICATE_EXPIRED' in result['stderr']:
                error = 'FATAL: SSL alert received: CERTIFICATE_EXPIRED\n' \
                        'IOException: SocketException cannot write on socket' in result['stderr']
            elif 'IOException' in result['stderr']:
                assert 'IOException: SocketException cannot write on socket' in result['stderr']
            else:
                error = "ATAL: SSL alert received: CERTIFICATE_UNKNOWN\n" \
                        "IOException: SocketException cannot write on socket"
                assert error in result['stderr']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run :  {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


def test_pki_kra_key_find_with_not_group_member(ansible_module):
    """
    :Title: Test pki kra-key-find with user who is not associated with any group.
    :Description: This pki kra-key-find with user who is not associated with any group.
    :Requirement: pki kra-key-find
    :CaseComponent: \-
    :Steps:
        1. generate a certificate which is not a member of any group.
        2. pki -n testuser1234 kra-key-find
    :ExpectedResults:
        1. Command should throw Authorization Error.
    """
    userid = "testuser21026_{}".format(random.randint(111111, 9999999))
    fullName = userid
    subject = "UID={},CN={}".format(userid, fullName)
    cert_file = "/tmp/{}.pem".format(userid)
    userop.add_user(ansible_module, 'add', userid=userid, user_name=fullName, subsystem='kra')
    log.info("Added user {}".format(userid))
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize=2048, profile='caUserCert')
    log.info("Created certificate with Cert ID: {}".format(cert_id))
    if cert_id:
        imported = ansible_module.command(basic_pki_cmd_ca + ' client-cert-import {} '
                                                             '--serial {}'.format(userid, cert_id))
        for result in imported.values():
            assert result['rc'] == 0
            log.info("Imported certificate to certdb.")
        exported = ansible_module.command(basic_pki_cmd_ca + ' ca-cert-show {} --output {}'.format(cert_id, cert_file))
        for result in exported.values():
            assert result['rc'] == 0
            log.info("Stored certificate to the file.")
        cert_add = ansible_module.pki(cli='kra-user-cert-add',
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.KRA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                      extra_args='{} --input {}'.format(userid, cert_file))
        for result in cert_add.values():
            if result['rc'] == 0:
                assert 'Added certificate' in result['stdout']
                log.info("Added certificate to the user.")
            else:
                log.error("Failed to add certificate to the user.")
                log.info(result['stdout'])
                log.error(result['stderr'])
                pytest.fail()
    key_find = ansible_module.pki(cli=pki_cmd,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  port=constants.KRA_HTTP_PORT,
                                  hostname=constants.MASTER_HOSTNAME,
                                  certnick='"{}"'.format(userid))
    for result in key_find.values():
        if result['rc'] >= 1:
            assert "ForbiddenException: Authorization Error" in result['stderr']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
    ansible_module.command('rm -rf {}'.format(cert_file))
    userop.remove_user(ansible_module, userid)
    ansible_module.command(basic_pki_cmd_ca + ' client-cert-del {}'.format(userid))
