#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI KRA KEY CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following kra-key-generate cli commands needs to be tested:
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
import re
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

pki_cmd = 'kra-key-generate'
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

client_cert_del = 'pki -d {} -c {} client-cert-del '.format(constants.NSSDB, constants.CLIENT_DATABASE_PASSWORD)


@pytest.mark.parametrize('args', ['--help', '', 'asdfa'])
def test_pki_kra_key_generate_help_option(ansible_module, args):
    """
    :Title: Test pki kra-key-generate with '' asdf and --help option
    :Description: Test pki kra-key-generate with '', asdf and --help option
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki kra-key-generate ''
        2. pki kra-key-generate --help
        3. pki kra-key-generate asdfa
    :ExpectedResults:
        1.
    """
    generate_key = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.KRA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                      extra_args=args)

    for result in generate_key.values():
        if args == '--help':
            assert 'usage: kra-key-generate <Client Key ID> --key-algorithm <algorithm>' in result['stdout']
            assert '                        [OPTIONS...]' in result['stdout']
            log.info("Successfully run:  {}".format(result['cmd']))
        elif args == '':
            assert 'ERROR: Missing Client Key Id' in result['stderr']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            assert 'ERROR: Missing key algorithm' in result['stderr']
            log.info("Successfully run: {}".format(result['cmd']))

@pytest.mark.parametrize('size', ['128', '192', '256'])
@pytest.mark.parametrize('usage', ['wrap', 'unwrap', 'sign', 'verify', 'encrypt', 'decrypt'])
def test_pki_kra_key_generate_with_AES_algo_diff_size_and_usages(ansible_module, size, usage):
    """
    :Title: Test pki kra-key-generate with AES algo diff size and usages
    :Description: Test pki kra-key-generate with AES algo diff size and usages
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki kra-key-generate <client_id> --key-algorithm 'AES' --key-size 128/256/192 --usage warp/unwarp/sign/verify
        encrypt/decrypt
    :ExpectedResults:
        1. It should generate the key for each of the usages with specified length
    """
    clientID = 'testuser21041_{}'.format(random.randint(11111, 99999999))
    generate_key = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.KRA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                      extra_args='"{}" --key-algorithm AES --key-size {} '
                                                 '--usages {}'.format(clientID, size, usage))
    for result in generate_key.values():
        if result['rc'] == 0:
            assert 'Key generation request info' in result['stdout']
            assert 'Request ID:' in result['stdout']
            assert 'Key ID:' in result['stdout']
            assert 'Type: symkeyGenRequest' in result['stdout']
            assert 'Status: complete' in result['stdout']

            req_id = re.findall('Request ID: .*', result['stdout'])
            request_id = req_id[0].split(":")[1].strip()

            key_id = key_library.review_key_request(ansible_module, request_id=request_id)
            log.info("Success: Key request approved. Key ID: {}".format(key_id))
            log.info('Successfully run : {}'.format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


@pytest.mark.parametrize('usages', ['wrap,unwrap,sign,verify,encrypt,decrypt',
                                    'wrap,unwrap,sign,verify,encrypt,decrypt,asdfaf', '', 'asdfa', '0'])
def test_pki_kra_key_generate_with_AES_algo_and_diff_key_usages(ansible_module, usages):
    """
    :Title: Test pki kra-key-generate with AES algo and diff key usages, '', asdfa, wrap,unwrap, 0
    :Description: Test pki kra-key-generate with AES algo and diff key usages, '', asdfa, wrap,unwrap, 0
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki kra-key-generate --key-size 128 --key-algorithm AES --usages wrap,unwrap,sign,verify,encrypt,decrypt
        2. pki kra-key-generate --key-size 128 --key-algorithm AES --usages ''
        3. pki kra-key-generate --key-size 128 --key-algorithm AES --usages asdfa
        4. pki kra-key-generate --key-size 128 --key-algorithm AES --usages '0'
    :ExpectedResults:
        1. It should generate the key.
        2. It should throw an error
        3. It should throw an error
        4. It should throw an error
    """

    clientID = 'testuser21042_{}'.format(random.randint(11111, 99999999))
    generate_key = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.KRA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                      extra_args='"{}" --key-algorithm AES --key-size 128 '
                                                 '--usages {}'.format(clientID, usages))
    for result in generate_key.values():
        if result['rc'] == 0:
            assert 'Key generation request info' in result['stdout']
            assert 'Request ID:' in result['stdout']
            assert 'Key ID:' in result['stdout']
            assert 'Type: symkeyGenRequest' in result['stdout']
            assert 'Status: complete' in result['stdout']

            req_id = re.findall('Request ID: .*', result['stdout'])
            request_id = req_id[0].split(":")[1].strip()

            key_id = key_library.review_key_request(ansible_module, request_id=request_id)
            log.info("Success: Key request approved. Key ID: {}".format(key_id))
            log.info('Successfully run : {}'.format(result['cmd']))
        elif usages == '':
            assert 'MissingArgumentException: Missing argument for option: usages' in result['stderr']
            log.info("Successfully run : {}".format(result['cmd']))
        elif usages in ['0', 'asdfa', 'wrap,unwrap,sign,verify,encrypt,decrypt,asdfaf']:
            if usages.endswith("asdfaf"):
                usage = usages.split(",")[-1].strip()
                assert 'IllegalArgumentException: Invalid usage "{}" specified.'.format(usage) in result['stderr']
            else:
                assert 'IllegalArgumentException: Invalid usage "{}" specified.'.format(usages) in result['stderr']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


@pytest.mark.parametrize('size', ['123184', '-123182', 'asdfa', '0', '128', '192', '256', '384'])
def test_pki_kra_key_generate_with_AES_algo_and_diff_key_sizes(ansible_module, size):
    """
    :Title: Test pki kra-key-generate with AES algo and diff key usages, '', asdfa, wrap,unwrap, 0
    :Description: Test pki kra-key-generate with AES algo and diff key usages, '', asdfa, wrap,unwrap, 0
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki kra-key-generate --key-size 128 --key-algorithm AES --usages wrap,unwrap,sign,verify,encrypt,decrypt
        2. pki kra-key-generate --key-size 128 --key-algorithm AES --usages ''
        3. pki kra-key-generate --key-size 128 --key-algorithm AES --usages asdfa
        4. pki kra-key-generate --key-size 128 --key-algorithm AES --usages '0'
    :ExpectedResults:
        1. It should generate the key.
        2. It should throw an error
        3. It should throw an error
        4. It should throw an error
    """

    clientID = 'testuser21043_{}'.format(random.randint(11111, 99999999))
    generate_key = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.KRA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                      extra_args='"{}" --key-algorithm AES --key-size {} '
                                                 '--usages "wrap,unwrap"'.format(clientID, size))
    for result in generate_key.values():
        if result['rc'] == 0:
            assert 'Key generation request info' in result['stdout']
            assert 'Request ID:' in result['stdout']
            assert 'Key ID:' in result['stdout']
            assert 'Type: symkeyGenRequest' in result['stdout']
            assert 'Status: complete' in result['stdout']

            req_id = re.findall('Request ID: .*', result['stdout'])
            request_id = req_id[0].split(":")[1].strip()

            key_id = key_library.review_key_request(ansible_module, request_id=request_id)
            log.info("Success: Key request approved. Key ID: {}".format(key_id))
            log.info('Successfully run : {}'.format(result['cmd']))
        elif size == '':
            assert 'MissingArgumentException: Missing argument for option: usages' in result['stderr']
            log.info("Successfully run : {}".format(result['cmd']))
        elif size in ['0', '123184', '-123182', '384']:
            assert 'BadRequestException' in result['stderr']
            log.info("Successfully run : {}".format(result['cmd']))
        elif size == 'asdfa':
            assert 'ERROR: Key size must be an integer.' in result['stderr']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


@pytest.mark.parametrize('size', ['8', '-3223', 'asdfa', '0', '128', '192', '256'])
def test_pki_kra_key_generate_with_RC2_algo_and_diff_key_sizes(ansible_module, size):
    """
    :Title: Test pki kra-key-generate with RC2 algorithm and different key sizes
    :Description: Test pki kra-key-generate with RC2 algorithm and different key sizes
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki kra-key-generate --key-algorithm RC2 --key-size 8
        2. pki kra-key-generate --key-algorithm RC2 --key-size 128
        3. pki kra-key-generate --key-algorithm RC2 --key-size asdfa
        4. pki kra-key-generate --key-algorithm RC2 --key-size 256
    :ExpectedResults:
        1. It should generate the key
        2. It should generate the key.
        3. It should fail with error message
        4. It should fail with error message.
    """
    clientID = 'testuser21044_{}'.format(random.randint(11111, 99999999))
    generate_key = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.KRA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                      extra_args='"{}" --key-algorithm RC2 --key-size {} '
                                                 '--usages "wrap,unwrap"'.format(clientID, size))
    for result in generate_key.values():
        if result['rc'] == 0:
            assert 'Key generation request info' in result['stdout']
            assert 'Request ID:' in result['stdout']
            assert 'Key ID:' in result['stdout']
            assert 'Type: symkeyGenRequest' in result['stdout']
            assert 'Status: complete' in result['stdout']

            req_id = re.findall('Request ID: .*', result['stdout'])
            request_id = req_id[0].split(":")[1].strip()

            key_id = key_library.review_key_request(ansible_module, request_id=request_id)
            log.info("Success: Key request approved. Key ID: {}".format(key_id))
            log.info('Successfully run : {}'.format(result['cmd']))
        elif size == '':
            assert 'MissingArgumentException: Missing argument for option: usages' in result['stderr']
            log.info("Successfully run : {}".format(result['cmd']))
        elif size in ['-3223', '0', '', '192', '256']:
            assert 'BadRequestException' in result['stderr']
            log.info("Successfully run : {}".format(result['cmd']))
        elif size == 'asdfa':
            assert 'ERROR: Key size must be an integer.' in result['stderr']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


@pytest.mark.parametrize('size', ['128', '256', '1024', 'asdfa'])
def test_pki_kra_key_generate_with_RC4_algo_and_diff_key_sizes(ansible_module, size):
    """
    :Title: Test pki kra-key-generate with RC2 algorithm and different key sizes
    :Description: Test pki kra-key-generate with RC2 algorithm and different key sizes
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki kra-key-generate --key-algorithm RC4 --key-size 0
        2. pki kra-key-generate --key-algorithm RC4 --key-size 128
        3. pki kra-key-generate --key-algorithm RC4 --key-size asdfa
        4. pki kra-key-generate --key-algorithm RC4 --key-size 256
        4. pki kra-key-generate --key-algorithm RC4 --key-size -3223
    :ExpectedResults:
        1. It should generate the key
        2. It should generate the key.
        3. It should fail with error message
        4. It should fail with error message.
    """
    clientID = 'testuser21045_{}'.format(random.randint(11111, 99999999))
    generate_key = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.KRA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                      extra_args='"{}" --key-algorithm RC4 --key-size "{}" '
                                                 '--usages "wrap,unwrap"'.format(clientID, size))
    for result in generate_key.values():
        if result['rc'] == 0:
            assert 'Key generation request info' in result['stdout']
            assert 'Request ID:' in result['stdout']
            if size not in ['-3223', '0']:
                assert 'Key ID:' in result['stdout']
            assert 'Type: symkeyGenRequest' in result['stdout']
            assert 'Status: complete' in result['stdout']

            req_id = re.findall('Request ID:.*', result['stdout'])
            request_id = req_id[0].split(":")[1].strip()

            key_id = key_library.review_key_request(ansible_module, request_id=request_id)
            log.info("Success: Key request approved. Key ID: {}".format(key_id))
            log.info('Successfully run : {}'.format(result['cmd']))
        elif size == '':
            assert 'MissingArgumentException: Missing argument for option: usages' in result['stderr']
            log.info("Successfully run : {}".format(result['cmd']))
        elif size in ['-3223', '0', '', '192', '256']:
            assert 'BadRequestException: Invalid key size for this algorithm' in result['stderr']
            log.info("Successfully run : {}".format(result['cmd']))
        elif size == 'asdfa':
            assert 'ERROR: Key size must be an integer.' in result['stderr']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


@pytest.mark.parametrize('usages', ['wrap', 'unwrap', 'sign', 'verify', 'encrypt', 'decrypt',
                                    'wrap,unwrap,sign,encrypt,decrypt', ''])
def test_pki_kra_key_generate_with_DESede_algo(ansible_module, usages):
    """
    :Title: Test pki kra-key-generate with DESede algorithm
    :Description: Test pki kra-key-generate with DESede algorithm
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki kra-key-genereate --key-algorithm DESede
    :ExpectedResults:
        1. It should generate the key and archive it.
    """
    clientID = 'testuser21046_{}'.format(random.randint(11111, 99999999))
    generate_key = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.KRA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                      extra_args='"{}" --key-algorithm DESede --usages "{}"'.format(clientID, usages))
    for result in generate_key.values():
        if result['rc'] == 0:
            assert 'Key generation request info' in result['stdout']
            assert 'Request ID:' in result['stdout']
            assert 'Key ID:' in result['stdout']
            assert 'Type: symkeyGenRequest' in result['stdout']
            assert 'Status: complete' in result['stdout']

            req_id = re.findall('Request ID:.*', result['stdout'])
            request_id = req_id[0].split(":")[1].strip()

            key_id = key_library.review_key_request(ansible_module, request_id=request_id)
            log.info("Success: Key request approved. Key ID: {}".format(key_id))
            log.info('Successfully run : {}'.format(result['cmd']))
        elif usages == '':
            assert 'IllegalArgumentException: Invalid usage "" specified.' in result['stderr']
            log.info('Successfully run : {}'.format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


@pytest.mark.parametrize('key_size', ['-3223', '0', '', '192', '256', 'asdfa', '1024', '2048', '4096'])
def test_pki_kra_key_generarte_with_RSA_algo_and_diff_key_size(ansible_module, key_size):
    """
    :Title: Test pki kra-key-genereate with RSA algo and different key sizes
    :Description: Test pki kra-key-genereate with RSA algo and different key sizes
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki kra-key-generate RSA --key-size 1024
        1. pki kra-key-generate RSA --key-size 2048
        1. pki kra-key-generate RSA --key-size 4096
    :ExpectedResults:
        1. It should generate key and archive it.
    """

    clientID = 'testuser21047_{}'.format(random.randint(11111, 99999999))
    generate_key = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.KRA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                      extra_args='"{}" --key-algorithm RSA --key-size "{}" '
                                                 '--usages "wrap,unwrap"'.format(clientID, key_size))
    for result in generate_key.values():
        if result['rc'] == 0:
            assert 'Key generation request info' in result['stdout']
            assert 'Request ID:' in result['stdout']
            assert 'Key ID:' in result['stdout']
            assert 'Type: asymkeyGenRequest' in result['stdout']
            assert 'Status: complete' in result['stdout']

            req_id = re.findall('Request ID:.*', result['stdout'])
            request_id = req_id[0].split(":")[1].strip()

            key_id = key_library.review_key_request(ansible_module, request_id=request_id)
            log.info("Success: Key request approved. Key ID: {}".format(key_id))
            log.info('Successfully run : {}'.format(result['cmd']))
        elif key_size in ['-3223', '0', '192', '256']:
            assert 'IllegalArgumentException: Invalid key size specified.' in result['stderr']
            log.info("Successfully run : {}".format(result['cmd']))
        elif key_size in ['asdfa', '']:
            assert 'ERROR: Key size must be an integer.' in result['stderr']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


@pytest.mark.parametrize('usages', ['wrap', 'unwrap', 'sign', 'verify', 'encrypt', 'decrypt',
                                    'wrap,unwrap,sign,encrypt,decrypt', '', 'asdfa'])
def test_pki_kra_key_generarte_with_DES3_algo_and_diff_key_size(ansible_module, usages):
    """
    :Title: Test pki kra-key-genereate with RSA algo and different key sizes
    :Description: Test pki kra-key-genereate with RSA algo and different key sizes
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki kra-key-generate DES3 --usages wrap
        2. pki kra-key-generate DES3 --usages unwrap
        3. pki kra-key-generate DES3 --usages sign
        4. pki kra-key-generate DES3 --usages verify
        5. pki kra-key-generate DES3 --usages encrypt
        6. pki kra-key-generate DES3 --usages decrypt
    :ExpectedResults:
        1. It should generate key and archive it.
    """

    clientID = 'testuser21048_{}'.format(random.randint(11111, 99999999))
    generate_key = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.KRA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                      extra_args='"{}" --key-algorithm DES3 --usages "{}"'.format(clientID, usages))
    for result in generate_key.values():
        if result['rc'] == 0:
            assert 'Key generation request info' in result['stdout']
            assert 'Request ID:' in result['stdout']
            assert 'Key ID:' in result['stdout']
            assert 'Type: symkeyGenRequest' in result['stdout']
            assert 'Status: complete' in result['stdout']

            req_id = re.findall('Request ID:.*', result['stdout'])
            request_id = req_id[0].split(":")[1].strip()

            key_id = key_library.review_key_request(ansible_module, request_id=request_id)
            log.info("Success: Key request approved. Key ID: {}".format(key_id))
            log.info('Successfully run : {}'.format(result['cmd']))
        elif result['rc'] >= 1 and usages in ['', 'asdfa']:
            if "ERROR: " in result['stderr']:
                assert 'ERROR: Missing argument for option: usages' in result['stderr']
                log.info('Successfully run : {}'.format(result['cmd']))
            else:
                assert 'IllegalArgumentException: Invalid usage "{}" specified'.format(usages) in result['stderr']
                log.info('Successfully run : {}'.format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


@pytest.mark.parametrize('key_size', ['-3223', '0', '', '192', '256', 'asdfa', "512", "768", "1024"])
def test_pki_kra_key_generarte_with_DSA_algo_and_diff_key_size(ansible_module, key_size):
    """
    :Title: Test pki kra-key-genereate with RSA algo and different key sizes
    :Description: Test pki kra-key-genereate with RSA algo and different key sizes
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki kra-key-generate RSA --key-size 1024
        1. pki kra-key-generate RSA --key-size 2048
        1. pki kra-key-generate RSA --key-size 4096
    :ExpectedResults:
        1. It should generate key and archive it.
    """

    clientID = 'testuser21049_{}'.format(random.randint(11111, 99999999))
    generate_key = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.KRA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                      extra_args='"{}" --key-algorithm DSA --key-size "{}" '
                                                 '--usages "wrap,unwrap"'.format(clientID, key_size))
    for result in generate_key.values():
        if result['rc'] == 0:
            assert 'Key generation request info' in result['stdout']
            assert 'Request ID:' in result['stdout']
            assert 'Key ID:' in result['stdout']
            assert 'Type: asymkeyGenRequest' in result['stdout']
            assert 'Status: complete' in result['stdout']

            req_id = re.findall('Request ID:.*', result['stdout'])
            request_id = req_id[0].split(":")[1].strip()

            key_id = key_library.review_key_request(ansible_module, request_id=request_id)
            log.info("Success: Key request approved. Key ID: {}".format(key_id))
            log.info('Successfully run : {}'.format(result['cmd']))
        elif key_size in ['-3223', '0', '192', '256']:
            assert 'IllegalArgumentException: Invalid key size specified.' in result['stderr']
            log.info("Successfully run : {}".format(result['cmd']))
        elif key_size in ['asdfa', '']:
            assert 'ERROR: Key size must be an integer.' in result['stderr']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

@pytest.mark.gating_tier1
@pytest.mark.parametrize('users', ['KRA_AdminV', 'KRA_AgentV', 'KRA_AuditV'])
def test_pki_kra_key_generate_using_valid_user_cert(ansible_module, users):
    """
    :Title: Test pki kra-key-generate using valid user cert
    :Description: Test pki kra-key-generate using valid user cert
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -n KRA_AdminV kra-key-generate --key-algorithm AES
        2. pki -n KRA_AgentV kra-key-generate --key-algorithm AES
        3. pki -n KRA_AuditV kra-key-generate --key-algorithm AES
    :ExpectedResults:
        1. Key should get generated.
        2. It should throw an error
        3. It should throw an error
    """
    clientID = 'testuser21050_{}'.format(random.randint(11111, 99999999))
    generate_key = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.KRA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(users),
                                      extra_args='"{}" --key-algorithm AES --key-size 192 '
                                                 '--usages "wrap,unwrap"'.format(clientID))
    for result in generate_key.values():
        if result['rc'] == 0 and users == 'KRA_AgentV':
            assert 'Key generation request info' in result['stdout']
            assert 'Request ID:' in result['stdout']
            assert 'Key ID:' in result['stdout']
            assert 'Type: symkeyGenRequest' in result['stdout']
            assert 'Status: complete' in result['stdout']

            req_id = re.findall('Request ID:.*', result['stdout'])
            request_id = req_id[0].split(":")[1].strip()

            key_id = key_library.review_key_request(ansible_module, request_id=request_id)
            log.info("Success: Key request approved. Key ID: {}".format(key_id))
            log.info('Successfully run : {}'.format(result['cmd']))
        else:
            assert "ForbiddenException: Authorization Error" in result['stderr']
            log.info('Successfully run : {}'.format(result['cmd']))


@pytest.mark.parametrize('users', ['KRA_AdminR', 'KRA_AuditR', 'KRA_AgentR'])
def test_pki_kra_key_generate_using_revoked_user_cert(ansible_module, users):
    """
    :Title: Test pki kra-key-generate using valid user cert
    :Description: Test pki kra-key-generate using valid user cert
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -n KRA_AdminR kra-key-generate --key-algorithm AES
        2. pki -n KRA_AgentR kra-key-generate --key-algorithm AES
        3. pki -n KRA_AuditR kra-key-generate --key-algorithm AES
    :ExpectedResults:
        1. Key should get generated.
        2. It should throw an error
        3. It should throw an error
    """
    clientID = 'testuser21051_{}'.format(random.randint(11111, 99999999))
    generate_key = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.KRA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(users),
                                      extra_args='"{}" --key-algorithm AES --key-size 128 '
                                                 '--usages "wrap,unwrap"'.format(clientID))
    for result in generate_key.values():
        if result['rc'] == 0:
            assert 'Key generation request info' in result['stdout']
            assert 'Request ID:' in result['stdout']
            assert 'Key ID:' in result['stdout']
            assert 'Type: symkeyGenRequest' in result['stdout']
            assert 'Status: complete' in result['stdout']

            log.error("Failed to run: {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
        else:
            assert 'FATAL: SSL alert received: CERTIFICATE_REVOKED' in result['stderr']
            log.info('Successfully run : {}'.format(result['cmd']))


@pytest.mark.parametrize('users', ['KRA_AdminE', 'KRA_AgentE', 'KRA_AuditE'])
def test_pki_kra_key_generate_using_expired_user_cert(ansible_module, users):
    """
    :Title: Test pki kra-key-generate using expired user cert
    :Description: Test pki kra-key-generate using expired user cert
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -n KRA_AdminE kra-key-generate --key-algorithm AES
        2. pki -n KRA_AgentE kra-key-generate --key-algorithm AES
        3. pki -n KRA_AuditE kra-key-generate --key-algorithm AES
    :ExpectedResults:
        1. Key should get generated.
        2. It should throw an error
        3. It should throw an error
    """
    clientID = 'testuser21052_{}'.format(random.randint(11111, 99999999))
    generate_key = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.KRA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(users),
                                      extra_args='"{}" --key-algorithm AES --key-size 192 '
                                                 '--usages "wrap,unwrap"'.format(clientID))
    for result in generate_key.values():
        if result['rc'] == 0:
            assert 'Key generation request info' in result['stdout']
            assert 'Request ID:' in result['stdout']
            assert 'Key ID:' in result['stdout']
            assert 'Type: symkeyGenRequest' in result['stdout']
            assert 'Status: complete' in result['stdout']

            req_id = re.findall('Request ID:.*', result['stdout'])
            request_id = req_id[0].split(":")[1].strip()

            key_id = key_library.review_key_request(ansible_module, request_id=request_id)
            log.info("Success: Key request approved. Key ID: {}".format(key_id))
            log.error("Failed to run: {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
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
            log.info('Successfully run : {}'.format(result['cmd']))


def test_pki_kra_key_generate_with_user_who_is_not_member_of_any_group(ansible_module):
    """
    :Title: KRA key-generate using user who is not member of any group
    :Description: KRA Key-generate using user who is not member of any group
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Add user.
        2. Issue certificate to user, add certificate to user
        3. Import certificate to client db and generate key using cert.
    :ExpectedResults:
        1. It should throw an exception.
    """
    clientID = 'testuser21053_{}'.format(random.randint(11111, 99999999))

    userid = "testuser21054_{}".format(random.randint(111111, 9999999999))
    fullName = "Test {}".format(userid)
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
    generate_key = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.KRA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(userid),
                                      extra_args='"{}" --key-algorithm AES --key-size 192 '
                                                 '--usages "wrap,unwrap"'.format(clientID))
    for result in generate_key.values():
        if result['rc'] == 0:
            assert 'Key generation request info' in result['stdout']
            assert 'Request ID:' in result['stdout']
            assert 'Key ID:' in result['stdout']
            assert 'Type: symkeyGenRequest' in result['stdout']
            assert 'Status: complete' in result['stdout']
            log.error("Failed to run: {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
        else:
            assert "ForbiddenException: Authorization Error" in result['stderr']
            log.info('Successfully run : {}'.format(result['cmd']))

    ansible_module.command('rm -rf {}'.format(cert_file))
    userop.remove_user(ansible_module, userid)
    ansible_module.command(basic_pki_cmd_ca + ' client-cert-del {}'.format(userid))


@pytest.mark.parametrize('size', ['128', '192', '256'])
@pytest.mark.parametrize('usage', ['wrap', 'unwrap', 'sign', 'verify', 'encrypt', 'decrypt'])
def test_pki_kra_key_generate_i18n_character_with_AES_algo_diff_size_and_usages(ansible_module, size, usage):
    """
    :id: 0f381fea-c045-49d1-b248-71441aeb54a3
    :parametrized: yes
    :Title: Test pki kra-key-generate i18n character with AES algo diff size and usages
    :Description: Test pki kra-key-generate i18n character with AES algo diff size and usages
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki kra-key-generate <client_id> --key-algorithm 'AES' --key-size 128/256/192 --usage warp/unwarp/sign/verify
        encrypt/decrypt
    :ExpectedResults:
        1. It should generate the key for each of the usages with specified length
    :Automated: yes
    """
    clientID = 'ÖrjanÄke{}'.format(random.randint(11111, 99999999))
    generate_key = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.KRA_HTTPS_PORT,
                                      protocol='https',
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                      extra_args='"{}" --key-algorithm AES --key-size {} '
                                                 '--usages {}'.format(clientID, size, usage))
    for result in generate_key.values():
        if result['rc'] == 0:
            assert 'Key generation request info' in result['stdout']
            assert 'Request ID:' in result['stdout']
            assert 'Key ID:' in result['stdout']
            assert 'Type: symkeyGenRequest' in result['stdout']
            assert 'Status: complete' in result['stdout']

            req_id = re.findall('Request ID: .*', result['stdout'])
            request_id = req_id[0].split(":")[1].strip()

            key_id = key_library.review_key_request(ansible_module, request_id=request_id)
            log.info("Success: Key request approved. Key ID: {}".format(key_id))
            log.info('Successfully run : {}'.format(result['cmd'].encode('utf-8')))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


@pytest.mark.parametrize('key_size', ['-3223', '0', '', '192', '256', 'asdfa', '1024', '2048', '4096'])
def test_pki_kra_key_generarte_i18n_character_with_RSA_algo_and_diff_key_size(ansible_module, key_size):
    """
    :id: 294e4565-cb81-4050-a799-072c97798207
    :parametrized: yes
    :Title: Test pki kra-key-genereate i18n character with RSA algo and different key sizes
    :Description: Test pki kra-key-generate i18n character with RSA algo and different key sizes
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki kra-key-generate RSA --key-size 1024
        1. pki kra-key-generate RSA --key-size 2048
        1. pki kra-key-generate RSA --key-size 4096
    :ExpectedResults:
        1. It should generate key and archive it.
    :Automated: yes
    """

    clientID = 'ÖrjanÄke{}'.format(random.randint(11111, 99999999))
    generate_key = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.KRA_HTTPS_PORT,
                                      protocol='https',
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                      extra_args='"{}" --key-algorithm RSA --key-size "{}" '
                                                 '--usages "wrap,unwrap"'.format(clientID, key_size))
    for result in generate_key.values():
        if result['rc'] == 0:
            assert 'Key generation request info' in result['stdout']
            assert 'Request ID:' in result['stdout']
            assert 'Key ID:' in result['stdout']
            assert 'Type: asymkeyGenRequest' in result['stdout']
            assert 'Status: complete' in result['stdout']

            req_id = re.findall('Request ID:.*', result['stdout'])
            request_id = req_id[0].split(":")[1].strip()

            key_id = key_library.review_key_request(ansible_module, request_id=request_id)
            log.info("Success: Key request approved. Key ID: {}".format(key_id))
            log.info('Successfully run : {}'.format(result['cmd'].encode('utf-8')))
        elif key_size in ['-3223', '0', '192', '256']:
            assert 'IllegalArgumentException: Invalid key size specified.' in result['stderr']
            log.info("Successfully run : {}".format(result['cmd'].encode('utf-8')))
        elif key_size in ['asdfa', '']:
            assert 'ERROR: Key size must be an integer.' in result['stderr']
            log.info("Successfully run : {}".format(result['cmd'].encode('utf-8')))
        else:
            log.error("Failed to run: {}".format(result['cmd'].encode('utf-8')))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
