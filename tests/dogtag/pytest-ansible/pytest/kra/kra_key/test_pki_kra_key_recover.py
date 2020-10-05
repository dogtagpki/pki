#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI KRA KEY CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following kra-key-recover cli commands needs to be tested:
#   pki kra-key-generate
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

pki_cmd = 'kra-key-recover'
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

key_types = ['AES', 'RSA', 'DSA']
key_lengths = {'AES': 128, 'RSA': 2048, 'DSA': 1024}


@pytest.mark.parametrize('args', ['--help', '', 'asdfa'])
def test_pki_kra_key_recover_help_message(ansible_module, args):
    """
    :Title: Test pki kra-key-recover with --help, '' and asdfa params
    :Description: Test pki kra-key-recover with --help, '' and asdfa params
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki kra-key-recover --help
        2. pki kra-key-recover ''
        3. pki kra-key-recover asdfa
    :ExpectedResults:
        1. It should show help message
        2. It should throw an Exception
        3. It should throw an Exception
    """

    help_out = ansible_module.pki(cli=pki_cmd,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  port=constants.KRA_HTTP_PORT,
                                  hostname=constants.MASTER_HOSTNAME,
                                  certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                  extra_args=args)
    for result in help_out.values():
        if args == '--help':
            assert "usage: kra-key-recover [OPTIONS...]" in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        elif args == '':
            assert "ERROR: Neither a key ID nor a request file's path is specified." in result['stderr']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            assert 'ERROR: Too many arguments specified.' in result['stderr']
            log.info("Successfully run: {}".format(result['cmd']))

@pytest.mark.gating_tier1
def test_pki_kra_key_recover_using_symmetric_key(ansible_module):
    """
    :Title: Test pki kra-key-recovery using approved symmetric key
    :Description: Test pki kra-key-recovery using approved symmetric key
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Generate symmetric key
        2. Recover generated key using pki kra-key-recovery
    :ExpectedResults:
        1. Key should get recoverd.
    """
    client_key_id = 'testuser21101_{}'.format(random.randint(1111111, 9999999))
    key_id = key_library.generate_key(ansible_module, algo='AES', client_key_id=client_key_id, key_size=128)
    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args="--keyID {}".format(key_id.get('key_id')))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Key Recovery Request Information" in result['stdout']
            assert "Request ID:" in result['stdout']
            assert "Key ID: {}".format(key_id.get('key_id')) in result['stdout']
            assert "Type: securityDataRecovery" in result['stdout']
            assert "Status: svc_pending" in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


def test_pki_kra_key_recover_using_asymmetric_key(ansible_module):
    """
    :Title: Test pki kra-key-recovery using approved Asymmetric key
    :Description: Test pki kra-key-recovery using approved Asymmetric key
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Generate Asymmetric key and approve it.
        2. Recover generated key using kra-key-recover
    :ExpectedResults:
        1. Key should get recovered.
    """
    client_key_id = 'testuser21102_{}'.format(random.randint(1111111, 9999999))
    key_id = key_library.generate_key(ansible_module, algo='RSA', client_key_id=client_key_id, key_size=2048)
    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args="--keyID {}".format(key_id.get('key_id')))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Key Recovery Request Information" in result['stdout']
            assert "Request ID: " in result['stdout']
            assert "Key ID: {}".format(key_id.get('key_id')) in result['stdout']
            assert "Type: securityDataRecovery" in result['stdout']
            assert "Status: svc_pending" in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

@pytest.mark.gating_tier1
def test_pki_kra_key_recover_archive_key_in_kra_and_recover(ansible_module):
    """
    :Title: Test pki kra-key-recover, archive key in KRA and recover it.
    :Description: Test pki kra-key-recover, archive key in KRA and recover it.
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Archive key in KRA
        2. Recover key using kra-key-recover.
    :ExpectedResults:
        1. Key should get recoverd.
    """
    client_key_id = 'testuser21103_{}'.format(random.randint(1111111, 9999999))
    key_id = key_library.archive_key(ansible_module, passphrase=constants.CLIENT_DATABASE_PASSWORD,
                                     client_key_id=client_key_id)

    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args="--keyID {}".format(key_id['key_id']))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Key Recovery Request Information" in result['stdout']
            assert "Request ID: " in result['stdout']
            assert "Key ID: " in result['stdout']
            assert "Type: securityDataRecovery" in result['stdout']
            assert "Status: svc_pending" in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


def test_pki_kra_key_recover_with_invalid_key_id(ansible_module):
    """
    :Title: Test pki kra-key-recovery with invalid key id
    :Description: Test pki kra-key-recovery with invalid key id
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Run pki kra-key-recover --keyID 0x21831923
    :ExpectedResults:
        1. It should throw an error message for that.
    """
    key_id = '0x89a2b4df3d9a0bc'
    cmd_out = ansible_module.pki(cli=pki_cmd,
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args="--keyID {}".format(key_id))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Key Recovery Request Information" in result['stdout']
            assert "Request ID: " in result['stdout']
            assert "Key ID: " in result['stdout']
            assert "Type: securityDataRecovery" in result['stdout']
            assert "Status: svc_pending" in result['stdout']
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
        else:
            assert "KeyNotFoundException: key not found" in result['stderr']
            log.info("Successfully run: {}".format(result['cmd']))
