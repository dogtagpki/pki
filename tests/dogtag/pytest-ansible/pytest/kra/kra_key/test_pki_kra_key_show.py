#!/usr/bin/python3
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI KRA KEY CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following kra-key-show cli commands needs to be tested:
#   pki kra-key-show
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Amol Kahat <akahat@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2019 Red Hat, Inc. All rights reserved.
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

pki_cmd = 'kra-key-show'
if TOPOLOGY != '01':
    CA_SUBJECT = 'CN=CA Signing Certificate,OU={},O={}'.format(constants.CA_INSTANCE_NAME,
                                                               constants.CA_SECURITY_DOMAIN_NAME)
else:
    CA_SUBJECT = 'CN=CA Signing Certificate,OU={},O={}'.format('pki-tomcat',
                                                               constants.CA_SECURITY_DOMAIN_NAME)

basic_pki_cmd_ca = 'pki -d {} -c {} -p {} -n "{}" '.format(constants.NSSDB,
                                                           constants.CLIENT_DIR_PASSWORD,
                                                           constants.CA_HTTP_PORT,
                                                           constants.CA_ADMIN_NICK)

group_del = 'pki -d {} -c {} -p {} -n "{}" ' \
            'ca-group-del '.format(constants.NSSDB, constants.CLIENT_DIR_PASSWORD,
                                   constants.CA_HTTP_PORT, constants.CA_ADMIN_NICK)

client_cert_del = 'pki -d {} -c {} client-cert-del '.format(constants.NSSDB,
                                                            constants.CLIENT_DIR_PASSWORD)


@pytest.mark.parametrize('subcmd', ['', '--help', 'asdfa'])
def test_pki_kra_key_show_help(ansible_module, subcmd):
    """
    :Title: Test pki kra-key-show with '' and '--help'
    :Description: Test pki kra-key-show command with '' and '--help'
    :Requirement: pki kra-key-find
    :CaseComponent: \-
    :Steps:
        1. pki kra-key-show
        2. pki kra-key-show --help
    :ExpectedResults:
        1. It should throw an excpetion
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
            assert 'usage: kra-key-show <Key ID> [OPTIONS...]' in result['stdout']
            assert '--clientKeyID <Client Key Identifier>   Unique client key identifier.' in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        elif subcmd == '':
            assert 'ERROR: Missing Key ID or Client Key ID.' in result['stderr']
            log.info("Successfully run: {}".format(result['cmd']))
        elif subcmd == 'asdfa':
            assert 'NumberFormatException: For input string: "asdfa"' in result['stderr']
            log.info("Successfully run: {}".format(result['cmd']))


@pytest.mark.parametrize('no', ['hex', 'dec'])
def test_pki_kra_key_show_with_diferent_valid_key_id(ansible_module, no):
    """
    :Title: Test pki kra-key-show with hex and decimal key id.
    :Description: Test pki kra-key-show with hex and decimal key id.
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Generate key
        2. Run kra-key-show <hex_key_id>
        3. Run kra-key-show <decimal_key_id>
    :ExpectedResults:
        1. It should show the key with hex_key_id
        2. It should show the key with decimal_key_id
    """
    client_key_id = 'testuser21151_{}'.format(random.randint(1111111, 9999999))
    key_id = key_library.generate_key(ansible_module, algo='AES', client_key_id=client_key_id, key_size=128)
    keyid = key_id['key_id']
    if no == 'dec':
        keyid = int(key_id['key_id'], 16)
    key_show_out = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.KRA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                      extra_args='{}'.format(keyid))

    for result in key_show_out.values():
        if result['rc'] == 0:
            assert 'Key ID: {}'.format(key_id['key_id']) in result['stdout']
            assert 'Client Key ID: {}'.format(client_key_id) in result['stdout']
            assert 'Status: active' in result['stdout']
            assert 'Owner: kraadmin' in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            log.info(result['cmd'])
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


@pytest.mark.parametrize('no', ['hex', 'dec'])
def test_pki_kra_key_show_with_diferent_invalid_key_id(ansible_module, no):
    """
    :Title: Test pki kra-key-show with hex and decimal invalid key id.
    :Description: Test pki kra-key-show with hex and decimal invalid key id.
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Generate key
        2. Run kra-key-show <invalid_hex_key_id>
        3. Run kra-key-show <invalid_decimal_key_id>
    :ExpectedResults:
        1. It should throw exception with invalid_hex_key_id
        2. It should throw exception with invalid_decimal_key_id
    """
    client_key_id = 'testuser21152_{}'.format(random.randint(1111111, 9999999))
    keyid = random.randint(11111111111, 99999999999999)
    if no == 'hex':
        keyid = hex(keyid)
    key_show_out = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.KRA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                      extra_args='{}'.format(keyid))

    for result in key_show_out.values():
        if result['rc'] == 0:
            assert 'Key ID:' in result['stdout']
            assert 'Client Key ID: {}'.format(client_key_id) in result['stdout']
            assert 'Status: active' in result['stdout']
            assert 'Owner: kraadmin' in result['stdout']
            log.info(result['cmd'])
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
        elif result['rc'] >= 1:
            assert "KeyNotFoundException: key not found" in result['stderr']
            log.info("Successfully run: {}".format(result['cmd']))


def test_pki_kra_key_show_with_archived_key(ansible_module):
    """
    :Title: Test pki kra-key-show with archived key
    :Description: Test pki kra-key-show with archived key.
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Archive the key. Approve the request
        2. Run pki kra-key-show <key_id>
    :ExpectedResults:
        1. It should show the key details.
    """
    client_key_id = 'testuser21153_{}'.format(random.randint(1111111, 9999999))
    key_request = key_library.archive_key(ansible_module, passphrase=constants.CLIENT_DATABASE_PASSWORD,
                                          client_key_id=client_key_id)
    key_id = key_library.review_key_request(ansible_module, key_request['request_id'])
    key_show_out = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.KRA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                      extra_args='{}'.format(key_id))

    for result in key_show_out.values():
        if result['rc'] == 0:
            assert 'Key ID: {}'.format(key_id) in result['stdout']
            assert 'Client Key ID: {}'.format(client_key_id) in result['stdout']
            assert 'Status: active' in result['stdout']
            assert 'Owner: kraadmin' in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))

        elif result['rc'] >= 1:
            log.info(result['cmd'])
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


@pytest.mark.parametrize('valid_cert', ['KRA_AdminV', 'KRA_AuditV', 'KRA_AgentV'])
def test_pki_kra_key_show_with_valid_certificates(ansible_module, valid_cert):
    """
    :Title: Test pki kra-key-show with valid certificate
    :Description: Test pki kra-key-show with valid certificate
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -n KRA_AdminV kra-key-show
        2. pki -n KRA_AgentV kra-key-show
        3. pki -n KRA_AuditV kra-key-show
    :ExpectedResults:
        1. KRA_AdminV should show the key.
        2. KRA_AuditV and KRA_AgentV should not show the key.
    """

    client_key_id = 'testuser21154_{}'.format(random.randint(1111111, 9999999))
    key_id = key_library.generate_key(ansible_module, algo='AES', client_key_id=client_key_id, key_size=128)
    keyid = key_id['key_id']

    key_show_out = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.KRA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(valid_cert),
                                      extra_args='{}'.format(keyid))

    for result in key_show_out.values():
        if result['rc'] == 0:
            assert 'Key ID: {}'.format(key_id['key_id']) in result['stdout']
            assert 'Client Key ID: {}'.format(client_key_id) in result['stdout']
            assert 'Status: active' in result['stdout']
            assert 'Owner: kraadmin' in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            assert "ForbiddenException: Authorization Error" in result['stderr']
            log.info("Successfully run: {}".format(result['cmd']))


@pytest.mark.parametrize('revoked_cert', ['KRA_AdminR', 'KRA_AuditR', 'KRA_AgentR'])
def test_pki_kra_key_show_with_revoked_certificates(ansible_module, revoked_cert):
    """
    :Title: Test pki kra-key-show with Revoked certificates
    :Description: Test pki kra-key-show with revoked certificates
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Generate key
        2. Run pki -n "KRA_AdminR" kra-key-show <key_id>
        3. Run pki -n "KRA_AuditR" kra-key-show <key_id>
        4. Run pki -n "KRA_AgentR" kra-key-show <key_id>
    :ExpectedResults:
        1. All the certs should throw an Exception.
    """
    client_key_id = 'testuser21154_{}'.format(random.randint(1111111, 9999999))
    key_id = key_library.generate_key(ansible_module, algo='AES', client_key_id=client_key_id, key_size=128)
    keyid = key_id['key_id']

    key_show_out = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.KRA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(revoked_cert),
                                      extra_args='{}'.format(keyid))

    for result in key_show_out.values():
        if result['rc'] == 0:
            assert 'Key ID: {}'.format(key_id['key_id']) in result['stdout']
            assert 'Client Key ID: {}'.format(client_key_id) in result['stdout']
            assert 'Status: active' in result['stdout']
            assert 'Owner: kraadmin' in result['stdout']
            log.error("Failed to run: {}".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
        else:
            assert 'FATAL: SSL alert received: CERTIFICATE_REVOKED' in result['stderr']
            log.info('Successfully run : {}'.format(result['cmd']))


@pytest.mark.parametrize('expired_certs', ['KRA_AdminE', 'KRA_AuditE', 'KRA_AgentE'])
def test_pki_kra_key_show_with_expired_certificates(ansible_module, expired_certs):
    """
    :Title: Test pki kra-key-show with expired certificates
    :Description: Test pki kra-key-show with expired certificates
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Generate key.
        2. Run pki -n KRA_AdminE kra-key-show
        3. Run pki -n KRA_AgentE kra-key-show
        4. Run pki -n KRA_AuditE kra-key-show
    :ExpectedResults:
        1. All certs should throw an exeption.
    """

    client_key_id = 'testuser21154_{}'.format(random.randint(1111111, 9999999))
    key_id = key_library.generate_key(ansible_module, algo='AES', client_key_id=client_key_id, key_size=128)
    keyid = key_id['key_id']

    key_show_out = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.KRA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(expired_certs),
                                      extra_args='{}'.format(keyid))

    for result in key_show_out.values():
        if result['rc'] == 0:
            assert 'Key ID: {}'.format(key_id['key_id']) in result['stdout']
            assert 'Client Key ID: {}'.format(client_key_id) in result['stdout']
            assert 'Status: active' in result['stdout']
            assert 'Owner: kraadmin' in result['stdout']
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()
        else:
            if 'CERTIFICATE_EXPIRED' in result['stderr']:
                error = 'FATAL: SSL alert received: CERTIFICATE_EXPIRED\n' \
                        'IOException: SocketException cannot write on socket' in result['stderr']
            elif 'IOException' in result['stderr']:
                assert 'IOException: SocketException cannot write on socket' in result['stderr']
            else:
                error = "ATAL: SSL alert received: CERTIFICATE_UNKNOWN\n" \
                        "IOException: SocketException cannot write on socket"
                assert error in result['stderr']
            log.info("Successfully run: {}".format(result['cmd']))
