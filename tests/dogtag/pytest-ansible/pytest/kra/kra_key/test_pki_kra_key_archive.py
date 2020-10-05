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
import base64
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
key_library = utils.pki_key_library(nssdb=constants.NSSDB)

pki_cmd = 'kra-key-archive'
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

key_request_template = {'description': 'Template for submitting a key archival request', 'clientKeyID': '',
                        'dataType': 'symmetricKey/passphrase/asymmetricKey', 'keyAlgorithm': '',
                        'keySize': '0', 'algorithmOID': '', 'symmetricAlgorithmParams': 'Base64 encoded NonceData',
                        'wrappedPrivateData': 'Base64 encoded session key wrapped secret',
                        'transWrappedSessionKey': 'Base64 encoded transport key wrapped session key',
                        'pkiArchiveOptions': 'Base 64 encoded PKIArchiveOptions object'}


@pytest.mark.parametrize('args', ['--help', '', 'asdfa'])
def test_pki_kra_key_archive_help(ansible_module, args):
    """
    :Title: Test pki kra-key-archive with --help, '' and 'asdfa'
    :Description: Test pki kra-key-archive with --help '' and 'asdfa'
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. run pki kra-key-archive --help
        2. run pki kra-key-archive ''
        3. run pki kra-key-archive asdfa
    :ExpectedResults:
        1. It should show help message.
        2.
        3.
    """
    output = ansible_module.pki(cli=pki_cmd,
                                nssdb=constants.NSSDB,
                                dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                port=constants.KRA_HTTP_PORT,
                                hostname=constants.MASTER_HOSTNAME,
                                certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                extra_args=args)
    for result in output.values():
        if args == '--help':
            assert "usage: kra-key-archive [OPTIONS...]" in result['stdout']
            assert "-clientKeyID <Client Key Identifier>   Unique client key identifier." in result['stdout']
            assert "                                        nickname." in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        elif args == '':
            assert result['rc'] >= 1
            assert "ERROR: Missing input data, passphrase, or request." in result['stderr']
            log.info("Successfully run: {}".format(result['cmd']))
        elif args == 'asdfa':
            assert result['rc'] >= 1
            assert "ERROR: Too many arguments specified." in result['stderr']
            log.info("Successfully run: {}".format(result['cmd']))

def test_pki_kra_key_archive_create_req_and_approve_it(ansible_module):
    """
    :Title: Test pki kra-key-archive, create passphrase archival request and verify approving it.
    :Description: Test pki kra-key-archive, create passphrase archival request and verify approving it.
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Run pki -p <port> -d <db> -c <password> kra-key-archive --clientKeyID <id> --passphrase <passphrase>
        2. Run pki -p <port> -d <db> -c <password> kra-key-request-review --action approve <request_id>
        3. Run pki -p <port> -d <db> -c <password> kra-key-retrieve --keyID <key_id>
    :ExpectedResults:
        1. key archival request should be succeed.
        2. Key archival request should be approved.
        3. Key should be successfully retrieved.
    """
    clientid = 'testuser21001_{}'.format(random.randint(1111, 99999999))
    passphrase = constants.CLIENT_DATABASE_PASSWORD
    b64_passphrase = base64.b64encode(passphrase.encode())
    archive_key = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.KRA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                     extra_args='--clientKeyID "{}" --passphrase "{}"'.format(clientid, passphrase))

    for result in archive_key.values():
        if result['rc'] == 0:
            assert 'Request ID:' in result['stdout']
            assert 'Key ID:' in result['stdout']
            assert 'Type: securityDataEnrollment' in result['stdout']
            assert 'Status: complete' in result['stdout']
            raw_req_id = re.findall(r'Request ID:.*', result['stdout'])
            request_id = raw_req_id[0].split(":")[1].strip()

            log.info("Key archival request completed. Key Request ID: {}".format(request_id))

            key_id = key_library.review_key_request(ansible_module, request_id, 'approve')
            log.info("Key archival request approved: Key ID: {}".format(key_id))
        else:
            log.error("Failed to create key archival request")
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    key_retrieve = ansible_module.pki(cli='kra-key-retrieve',
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.KRA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                      extra_args='--keyID "{}"'.format(key_id))
    for results in key_retrieve.values():
        if results['rc'] == 0:
            assert '{}'.format(b64_passphrase.decode('UTF-8')) in results['stdout']
            log.info("Successfully run: {}".format(results['cmd']))
        else:
            log.error("Failed to run : {}".format(results['cmd']))
            log.info(results['stdout'])
            log.error(results['stderr'])
            pytest.fail()


@pytest.mark.parametrize('passphrase', ['special_chars', 'length_100', ''])
def test_pki_kra_key_archive_with_passphrase_as_special_chars(ansible_module, passphrase):
    """
    :Title: Test pki kra-key-archive with passphrase as special characters
    :Description: Test pki kra-key-archive with passphrase as special characters
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Create archival key request.
        2. Approve key request.
        3. Retrieve key request
    :ExpectedResults:
        1. Retrieved key should show the archived data.
    """

    clientid = 'testuser21002_{}'.format(random.randint(1111, 99999999))
    passphrase = constants.CLIENT_DATABASE_PASSWORD
    b64_passphrase = base64.b64encode(passphrase.encode())
    if passphrase == 'special_chars':
        passphrase = constants.CLIENT_DATABASE_PASSWORD + '?%^()-'
        b64_passphrase = base64.b64encode(passphrase.encode())
    elif passphrase == 'length_100':
        passphrase, _, _ = utils.system_cmd("openssl rand -base65 100 | perl -p -e 's/\n//'")
        b64_passphrase = base64.b64encode(passphrase.encode())
    elif passphrase == '':
        passphrase = ''
    archive_key = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.KRA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                     extra_args='--clientKeyID "{}" --passphrase "{}"'.format(clientid, passphrase))

    for result in archive_key.values():
        if result['rc'] == 0:
            assert 'Request ID:' in result['stdout']
            assert 'Key ID:' in result['stdout']
            assert 'Type: securityDataEnrollment' in result['stdout']
            assert 'Status: complete' in result['stdout']
            raw_req_id = re.findall(r'Request ID:.*', result['stdout'])
            request_id = raw_req_id[0].split(":")[1].strip()

            log.info("Key archival request completed. Key Request ID: {}".format(request_id))

            key_id = key_library.review_key_request(ansible_module, request_id, 'approve')
            log.info("Key archival request approved: Key ID: {}".format(key_id))
        elif passphrase == '':
            assert result['rc'] >= 1
            assert 'MissingArgumentException: Missing argument for option: passphrase' in result['stderr']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            log.error("Failed to create key archival request")
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    if passphrase != '':
        key_retrieve = ansible_module.pki(cli='kra-key-retrieve',
                                          nssdb=constants.NSSDB,
                                          dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                          port=constants.KRA_HTTP_PORT,
                                          hostname=constants.MASTER_HOSTNAME,
                                          certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                          extra_args='--keyID "{}"'.format(key_id))
        for results in key_retrieve.values():
            if results['rc'] == 0:
                assert '{}'.format(b64_passphrase.decode('utf-8')) in results['stdout']
                log.info("Successfully run: {}".format(results['cmd']))
            else:
                log.error("Failed to run : {}".format(results['cmd']))
                log.info(results['stdout'])
                log.error(results['stderr'])
                pytest.fail()


@pytest.mark.parametrize('options', ['', 'valid'])
def test_pki_kra_key_archive_with_diff_input_to_clientkeyid(ansible_module, options):
    """
    :Title: Test pki kra-key-archive with different input to clientKeyID
    :Description: Test pki kra-key-archive with different input to clientKeyID
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki kra-key-archive --clientKeyID ''
        2. pki kra-key-archive --clientKeyID asdfa
        3. pki kra-key-archive --clientKeyID <valid_key_id>
    :ExpectedResults:
        1. It should throw an error
        2. It should throw an error
        3. It should archive the key.
    """

    passphrase = constants.CLIENT_DATABASE_PASSWORD
    b64_passphrase = base64.b64encode(passphrase.encode())
    extra_args = ''
    if options == '':
        extra_args = "--clientKeyID --passphrase '{}'".format(passphrase)
    elif options == 'valid':
        clientid = 'testuser21003_{}'.format(random.randint(1111, 99999999))
        extra_args = "--clientKeyID '{}' --passphrase '{}'".format(clientid, passphrase)

    archive_key = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.KRA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                     extra_args=extra_args)

    for result in archive_key.values():
        if result['rc'] == 0:
            assert 'Request ID:' in result['stdout']
            assert 'Key ID:' in result['stdout']
            assert 'Type: securityDataEnrollment' in result['stdout']
            assert 'Status: complete' in result['stdout']
            raw_req_id = re.findall(r'Request ID:.*', result['stdout'])
            request_id = raw_req_id[0].split(":")[1].strip()

            log.info("Key archival request completed. Key Request ID: {}".format(request_id))

            key_id = key_library.review_key_request(ansible_module, request_id, 'approve')
            log.info("Key archival request approved: Key ID: {}".format(key_id))
        elif options == '':
            assert result['rc'] >= 1
            assert 'MissingArgumentException: Missing argument for option: clientKeyID' in result['stderr']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            log.error("Failed to create key archival request")
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    if options != '':
        key_retrieve = ansible_module.pki(cli='kra-key-retrieve',
                                          nssdb=constants.NSSDB,
                                          dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                          port=constants.KRA_HTTP_PORT,
                                          hostname=constants.MASTER_HOSTNAME,
                                          certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                          extra_args='--keyID "{}"'.format(key_id))
        for results in key_retrieve.values():
            if results['rc'] == 0:
                assert '{}'.format(b64_passphrase.decode('UTF-8')) in results['stdout']
                log.info("Successfully run: {}".format(results['cmd']))
            else:
                log.error("Failed to run : {}".format(results['cmd']))
                pytest.fail()


@pytest.mark.rsa_pss
@pytest.mark.gating_tier1
@pytest.mark.parametrize('certnick', ['KRA_AdminV', 'KRA_AgentV', 'KRA_AuditV'])
def test_pki_kra_key_archive_with_valid_certificates(ansible_module, certnick):
    """
    :Title: Test pki kra-key-archive with valid certificates
    :Description: Test pki kra-key-archive with valid certificates
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -n KRA_AdminV kra-key-archive --clentKeyID <client_key_id> --passphrase SECret.123
        2. pki -n KRA_AgentV kra-key-archive --clentKeyID <client_key_id> --passphrase SECret.123
        3. pki -n KRA_AuditV kra-key-archive --clentKeyID <client_key_id> --passphrase SECret.123
    :ExpectedResults:
        1. It should throw an error
        2. It should archive key successfully
        3. It should throw an error
    """
    client_id = 'testuser21004_{}'.format(random.randint(1111, 99999999))
    passphrase = constants.CLIENT_DATABASE_PASSWORD

    archive_key = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.KRA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(certnick),
                                     extra_args='--clientKeyID "{}" --passphrase "{}"'.format(client_id, passphrase))

    for result in archive_key.values():
        if result['rc'] == 0:
            assert 'Request ID:' in result['stdout']
            assert 'Key ID:' in result['stdout']
            assert 'Type: securityDataEnrollment' in result['stdout']
            assert 'Status: complete' in result['stdout']
            if certnick == 'KRA_AgentV':
                log.info("Successfully run: {}".format(result['cmd']))
            else:
                log.error("Failed to run command: {}".format(result['cmd']))
                log.info(result['stdout'])
                log.error(result['stderr'])
                pytest.fail()
        else:
            assert result['rc'] >= 1
            assert 'ForbiddenException: Authorization Error' in result['stderr']
            log.info("Successfully run: {}".format(result['cmd']))

@pytest.mark.gating_tier1
@pytest.mark.parametrize('certnick', ['KRA_AdminR', 'KRA_AgentR', 'KRA_AuditR'])
def test_pki_kra_key_archive_with_revoked_certificates(ansible_module, certnick):
    """
    :Title: Test pki kra-key-archive with revoked certificates
    :Description: Test pki kra-key-archive with revoked certificates
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -n KRA_AdminR kra-key-archive --clientKeyID 'testuser101' --passphrase SECret.123
        3. pki -n KRA_AgentR kra-key-archive --clientKeyID 'testuser101' --passphrase SECret.123
        3. pki -n KRA_AuditR kra-key-archive --clientKeyID 'testuser101' --passphrase SECret.123
    :ExpectedResults:
        1. For all revoked certs it should throw an error.
    """
    client_id = 'testuser21005_{}'.format(random.randint(1111, 99999999))
    passphrase = constants.CLIENT_DATABASE_PASSWORD

    archive_key = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.KRA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(certnick),
                                     extra_args='--clientKeyID "{}" --passphrase "{}"'.format(client_id, passphrase))

    for result in archive_key.values():
        if result['rc'] == 0:
            assert 'Request ID:' in result['stdout']
            assert 'Key ID:' in result['stdout']
            assert 'Type: securityDataEnrollment' in result['stdout']
            assert 'Status: complete' in result['stdout']
            log.error("Failed to run command: {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
        else:
            assert result['rc'] >= 1
            if 'CERTIFICATE_REVOKED' in result['stderr']:
                error = 'FATAL: SSL alert received: CERTIFICATE_REVOKED\n' \
                        'IOException: SocketException cannot write on socket' in result['stderr']
            else:
                error = "ATAL: SSL alert received: CERTIFICATE_UNKNOWN\n" \
                        "IOException: SocketException cannot write on socket"
            assert error in result['stderr']
            log.info("Successfully run: {}".format(result['cmd']))


@pytest.mark.parametrize('certnick', ['KRA_AdminE', 'KRA_AgentE', 'KRA_AuditE'])
def test_pki_kra_key_archive_with_revoked_certificates(ansible_module, certnick):
    """
    :Title: Test pki kra-key-archive with Expired certificates
    :Description: Test pki kra-key-archive with expired certificates
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -n KRA_AdminE kra-key-archive --clientKeyID 'testuser101' --passphrase SECret.123
        3. pki -n KRA_AgentE kra-key-archive --clientKeyID 'testuser101' --passphrase SECret.123
        3. pki -n KRA_AuditE kra-key-archive --clientKeyID 'testuser101' --passphrase SECret.123
    :ExpectedResults:
        1. For all revoked certs it should throw an error.
    """
    client_id = 'testuser21006_{}'.format(random.randint(1111, 99999999))
    passphrase = constants.CLIENT_DATABASE_PASSWORD

    archive_key = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.KRA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(certnick),
                                     extra_args='--clientKeyID "{}" --passphrase "{}"'.format(client_id, passphrase))

    for result in archive_key.values():
        if result['rc'] == 0:
            assert 'Request ID:' in result['stdout']
            assert 'Key ID:' in result['stdout']
            assert 'Type: securityDataEnrollment' in result['stdout']
            assert 'Status: complete' in result['stdout']
            log.error("Failed to run command: {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
        else:
            assert result['rc'] >= 1
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

def test_pki_kra_key_archival_using_normal_user(ansible_module):
    """
    :Title: Test pki kra-key-archival request using normal user
    :Description: Test pki kra-key-archival request using normal user
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Create user
        2. Create cert, add cert to user
        3. Import cert to client db
        4. Create key archive request using imported certificate.
    :ExpectedResults:
        1. It should throw an exception
    """
    userid = "testuser21007_{}".format(random.randint(11111, 99999999))
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
        print(imported)
        for result in imported.values():
            assert result['rc'] == 0
            log.info("Imported certificate to certdb.")
        expored = ansible_module.command(basic_pki_cmd_ca + ' ca-cert-show {} --output {}'.format(cert_id, cert_file))
        for result in expored.values():
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
                                  certnick='"{}"'.format(userid),
                                  extra_args='--clientKeyID "{}" '
                                             '--passphrase "{}"'.format(userid, constants.CLIENT_DATABASE_PASSWORD))
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


def test_pki_kra_key_archive_with_transport_cert_nick(ansible_module):
    """
    :Title: Test pki kra-key-archive with transport cert nickname
    :Description: Test pki kra-key-archive with transport cert nickname
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki kra-key-archive --clientKeyID testuser1 --passphrase SECret.123
        --transport "DRM Transport Certificate - topology-02_Foobarmaster.org"
    :ExpectedResults:
        1. Certificate request should be made successfully.
    """
    client_id = 'testuser21009_{}'.format(random.randint(1111, 99999999))
    passphrase = constants.CLIENT_DATABASE_PASSWORD
    transport_nick = 'DRM Transport Certificate - {}'.format(constants.CA_SECURITY_DOMAIN_NAME)
    archive_key = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.KRA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                     extra_args='--clientKeyID "{}" --passphrase "{}" '
                                                '--transport "{}"'.format(client_id, passphrase, transport_nick))

    for result in archive_key.values():
        if result['rc'] == 0:
            assert 'Request ID:' in result['stdout']
            assert 'Key ID:' in result['stdout']
            assert 'Type: securityDataEnrollment' in result['stdout']
            assert 'Status: complete' in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            log.error("Failed to run command: {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


def test_pki_kra_key_archive_with_invalid_transport_nick(ansible_module):
    """
    :Title: Test pki kra-key-archive with invalid transport nick
    :Description: Test pki kra-key-archive with invalid transport nick
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki kra-key-archive --clientKeyID testuser1 --passphrase SECret.123 --transport "asdfa"
    :ExpectedResults:
        1. It should throw an error.
    """
    client_id = 'testuser21010_{}'.format(random.randint(1111, 99999999))
    passphrase = constants.CLIENT_DATABASE_PASSWORD
    transport_nick = 'asdfa'
    archive_key = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.KRA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                     extra_args='--clientKeyID "{}" --passphrase "{}" '
                                                '--transport "{}"'.format(client_id, passphrase, transport_nick))

    for result in archive_key.values():
        if result['rc'] == 0:
            assert 'Request ID:' in result['stdout']
            assert 'Key ID:' in result['stdout']
            assert 'Type: securityDataEnrollment' in result['stdout']
            assert 'Status: complete' in result['stdout']
            log.error("Failed to run command: {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
        else:
            assert result['rc'] >= 1
            assert 'ObjectNotFoundException: Certificate not found: asdfa' in result['stderr']
            log.info("Successfully run: {}".format(result['cmd']))


def test_pki_kra_key_archive_using_input_data_option(ansible_module):
    """
    :Title: Test pki kra-key-archive with --input-data option.
    :Description: Test pki kra-key-archive with --input-data option
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki kra-key-archive --clientKeyID testuser101 --input-data /file/
    :ExpectedResults:
        1. Key should get archived with --input-data option.
    """
    client_id = 'testuser21011_{}'.format(random.randint(1111, 99999999))
    passphrase = constants.CLIENT_DATABASE_PASSWORD
    passphrase_file = '/tmp/passphrase.txt'
    ansible_module.copy(content=passphrase, dest=passphrase_file)
    archive_key = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.KRA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                     extra_args='--clientKeyID "{}" --input-data {}'.format(client_id, passphrase_file))

    for result in archive_key.values():
        if result['rc'] == 0:
            assert 'Request ID:' in result['stdout']
            assert 'Key ID:' in result['stdout']
            assert 'Type: securityDataEnrollment' in result['stdout']
            assert 'Status: complete' in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            assert 'NoSuchFileException: /tmp/passphrase.txt' in result['stderr']
            log.error("Failed to run command: {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


def test_pki_kra_key_archive_using_input_data_option_with_invalid_input(ansible_module):
    """
    :Title: Test pki kra-key-archive with --input-data option with invalid input.
    :Description: Test pki kra-key-archive with --input-data option with invalid input
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki kra-key-archive --clientKeyID testuser101 --input-data /invalid_input_file.txt
    :ExpectedResults:
        1. It should throw an exception.
    """
    client_id = 'testuser21012_{}'.format(random.randint(1111, 99999999))
    passphrase = constants.CLIENT_DATABASE_PASSWORD
    passphrase_file = '/tmp/asdfasdfa.txt'
    archive_key = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.KRA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                     extra_args='--clientKeyID "{}" --input-data {}'.format(client_id, passphrase_file))

    for result in archive_key.values():
        if result['rc'] == 0:
            assert 'Request ID:' in result['stdout']
            assert 'Key ID:' in result['stdout']
            assert 'Type: securityDataEnrollment' in result['stdout']
            assert 'Status: complete' in result['stdout']
            log.error("Failed to run command: {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
        else:
            assert result['rc'] >= 1
            assert 'NoSuchFileException: {}'.format(passphrase_file) in result['stderr']
            log.info("Successfully run: {}".format(result['cmd']))

# TODO need to know how to use template and OIDS etc.
# def test_pki_kra_key_archive_using_input_option(ansible_module):
#     """
#     :Title: Test pki kra-key-archive using input option
#     :Description: Test pki kra-key-archive using input option
#     :Requirement:
#     :CaseComponent: \-
#     :Setup: Use the subsystems setup in ansible to run subsystem commands
#     :Steps:
#         1. pki kra-key-archive --input template.xml
#     :ExpectedResults:
#         1. It should create the key archival request.
#     """
#
#     root = etree.Element('KeyArchivalRequest')
#     attributes = etree.Element('Attributes')
#     className = etree.Element('ClassName')
#     className.text = 'com.netscape.certsrv.key.KeyArchivalReques'
#     root.append(attributes)
#     root.append(className)
#     for i, j in key_request_template.items():
#         child = etree.Element('Attribute', name=i)
#         child.text = j
#         attributes.append(child)
#
#     s = etree.tostring(root, pretty_print=True)
#     print(s)


# TODO --relam remaining
# TODO what is use of --relam?

def test_pki_kra_key_archive_with_i18n_character_create_req_and_approve_it(ansible_module):
    """
    :id: 3f5d1b3c-083f-42ec-b1cd-248d3fc03eca
    :Title: Test pki kra-key-archive with i18n character, create passphrase archival request and verify approving it.
    :Description: Test pki kra-key-archive with i18n character, create passphrase archival request
                  and verify approving it.
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Run pki -p <port> -d <db> -c <password> kra-key-archive --clientKeyID <id> --passphrase <passphrase>
        2. Run pki -p <port> -d <db> -c <password> kra-key-request-review --action approve <request_id>
        3. Run pki -p <port> -d <db> -c <password> kra-key-retrieve --keyID <key_id>
    :ExpectedResults:
        1. key archival request should be succeed.
        2. Key archival request should be approved.
        3. Key should be successfully retrieved.
    :Automated: Yes
    """
    clientid = 'ÖrjanÄke_{}'.format(random.randint(1111, 99999999))
    passphrase = constants.CLIENT_DATABASE_PASSWORD
    b64_passphrase = base64.b64encode(passphrase.encode())
    archive_key = ansible_module.pki(cli=pki_cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.KRA_HTTPS_PORT,
                                     protocol='https',
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                     extra_args='--clientKeyID "{}" --passphrase "{}"'.format(clientid, passphrase))

    for result in archive_key.values():
        if result['rc'] == 0:
            assert 'Request ID:' in result['stdout']
            assert 'Key ID:' in result['stdout']
            assert 'Type: securityDataEnrollment' in result['stdout']
            assert 'Status: complete' in result['stdout']
            raw_req_id = re.findall(r'Request ID:.*', result['stdout'])
            request_id = raw_req_id[0].split(":")[1].strip()

            log.info("Key archival request completed. Key Request ID: {}".format(request_id))

            key_id = key_library.review_key_request(ansible_module, request_id, 'approve')
            log.info("Key archival request approved: Key ID: {}".format(key_id))
        else:
            log.error("Failed to create key archival request")
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    key_retrieve = ansible_module.pki(cli='kra-key-retrieve',
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.KRA_HTTPS_PORT,
                                      protocol='https',
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                      extra_args='--keyID "{}"'.format(key_id))
    for results in key_retrieve.values():
        if results['rc'] == 0:
            assert '{}'.format(b64_passphrase.decode('UTF-8')) in results['stdout']
            log.info("Successfully run: {}".format(results['cmd']))
        else:
            log.error("Failed to run : {}".format(results['cmd']))
            log.info(results['stdout'])
            log.error(results['stderr'])
            pytest.fail()
