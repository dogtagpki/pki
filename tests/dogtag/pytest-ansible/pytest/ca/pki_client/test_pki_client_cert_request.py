#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI CLIENT CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki client cli commands needs to be tested:
#   pki client-cert-request
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
import tempfile
import time

import pytest
import requests

from pki.testlib.common import utils

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
userop = utils.UserOperations(nssdb=constants.NSSDB)

db2 = '/tmp/db2_test'

non_role_user = '$NonRoleUser$'
default_profile = 'caUserCert'
ec_default_profile = 'caECUserCert'
request_success_log = '[AuditEvent=PROFILE_CERT_REQUEST][SubjectID={}][Outcome=Success][ReqID={}]' \
                      '[ProfileID={}][CertSubject={}] ' \
                      'certificate request made with certificate profiles'
request_reject_log = '[AuditEvent=CERT_REQUEST_PROCESSED][SubjectID={}][Outcome=Failure]' \
                     '[ReqID={}][InfoName=rejectReason][InfoValue=Request {} Rejected - Key ' \
                     'Parameters 1024,2048,3072,4096 Not Matched] certificate request processed'

TOPOLOGY = constants.CA_INSTANCE_NAME.split("-")[-2]

if TOPOLOGY == '01':
    instance_name = 'pki-tomcat'
    topology_name = 'topology-01-CA'
    audit_cert_nick = 'auditSigningCert cert-{} CA'.format(instance_name)
else:
    instance_name = constants.CA_INSTANCE_NAME
    topology_name = constants.CA_INSTANCE_NAME
    audit_cert_nick = 'auditSigningCert cert-{} CA'.format(constants.CA_INSTANCE_NAME)

CA_SUBJECT = 'CN=CA Signing Certificate,OU={},O={}'.format(instance_name, constants.CA_SECURITY_DOMAIN_NAME)


def get_logs(ansible_module, lines=300, audit_logs=True):
    """
    :param ansible_modules:
    :param audit_logs:
    :return:
    """
    logs = None
    if audit_logs:
        time.sleep(15)
        logs = 'tail -n {} /var/log/pki/{}/ca/signedAudit/' \
               'ca_audit'.format(lines, instance_name)
    logs_out = ansible_module.command(logs)
    for result in logs_out.values():
        if result['rc'] == 0:
            return result['stdout']
        else:
            return None

@pytest.mark.parametrize('args', ['--help', 'asdfa', ''])
def test_pki_client_cert_request_help(ansible_module, args):
    """
    :Title: Test pki client-cert-request --help command.
    :Description: test pki client-cert-request --help command
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :ExpectedResults: Verify whether pki client-cert-request --help command shows help options.
    """
    help_cmd = ' pki client-cert-request {}'.format(args)
    help_out = ansible_module.command(help_cmd)
    for result in help_out.values():
        if result['rc'] == 0:
            assert "usage: client-cert-request [Subject DN] [OPTIONS...]" in result['stdout']
            assert "--algorithm <algorithm name>   Algorithm (default: rsa)" in result['stdout']
            assert "--help                         Show help message." in result['stdout']
            assert "--username <username>          Username for request authentication" in  result['stdout']
        elif args == '':
            assert 'ERROR: Missing subject DN or request username.' in result['stderr']
        elif args == 'asdfa':
            assert 'ERROR: Unable to generate CSR: Command failed. RC: 1' in result['stderr']
        else:
            pytest.fail("Failed to run pki cert-request {} command".format(args))


def test_pki_client_cert_request_general_req(ansible_module):
    """
    :Title: Test pki client-cert-request, create certificate request.
    :Description: test pki client-cert-request command
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :ExpectedResults: Verify whether pki client-cert-request command generates cert request.
    """
    user = 'testuser{}'.format(random.randint(1111, 99999))
    subject = 'UID={},CN=User {}'.format(user, user)
    cert_req = 'pki -d {} -c {} -h {} -P {} -p {} client-cert-request ' \
               '"{}"'.format(db2, constants.CLIENT_DIR_PASSWORD, constants.MASTER_HOSTNAME, constants.PROTOCOL_UNSECURE,
                             constants.CA_HTTP_PORT, subject)
    cert_req_out = ansible_module.command(cert_req)
    for result in cert_req_out.values():
        if result['rc'] == 0:
            assert 'Request ID: ' in result['stdout']
            assert 'Type: enrollment' in result['stdout']
            assert 'Request Status: pending' in result['stdout']
            assert 'Operation Result: success' in result['stdout']
            log.info("Successfully run '{}'".format(cert_req))

            request_id_raw = re.findall('Request ID: [\w].*', result['stdout'])
            request_id = request_id_raw[0].split(":")[1].strip()
            log.info("Checking logs.")
            logs = get_logs(ansible_module)
            profile_cert_req_logs = ",".join(re.findall('.*PROFILE_CERT_REQUEST.*', logs))
            new_log = request_success_log.format(non_role_user, request_id, default_profile,
                                                 subject)
            assert new_log in profile_cert_req_logs
            log.info("Verified the logs. Found log:\n{}\n".format(new_log))
        else:
            log.info("Failed to run '{}'".format(cert_req))
            pytest.fail("Failed to run '{}'".format(cert_req))


@pytest.mark.parametrize('key_len', ['', '1024', '2048', '3072', '4096', '5120', '9216',
                                     pytest.param('1321', marks=pytest.mark.fail)])
def test_pki_client_cert_request_algorithm_rsa_and_length(ansible_module, key_len):
    """
    :Title: Test pki client-cert-request, create request with algorithm rsa.
    :Description: test pki client-cert-request --algorithm command
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :ExpectedResults: Verify whether pki client-cert-request --algorithm command generates cert
    request.
    """
    user = 'testuser{}'.format(random.randint(1111, 99999))
    subject = 'UID={},CN=User {}'.format(user, user)
    cert_req = 'pki -d {} -c {} -h {} -P {} -p {} client-cert-request ' \
               '"{}" --algorithm rsa --length {}'.format(db2, constants.CLIENT_DIR_PASSWORD,
                                                         constants.MASTER_HOSTNAME,constants.PROTOCOL_UNSECURE,
                                                         constants.CA_HTTP_PORT,subject, key_len)
    cert_req_out = ansible_module.command(cert_req)
    for result in cert_req_out.values():
        if result['rc'] == 0:
            if not int(key_len) > 4096 and key_len != '1321':
                assert 'Request ID: ' in result['stdout']
                assert 'Type: enrollment' in result['stdout']
                assert 'Request Status: pending' in result['stdout']
                assert 'Operation Result: success' in result['stdout']
                log.info("Successfully run '{}'".format(cert_req))

                request_id_raw = re.findall('Request ID: [\w].*', result['stdout'])
                request_id = request_id_raw[0].split(":")[1].strip()
                log.info("Checking logs.")
                logs = get_logs(ansible_module)
                profile_cert_req_logs = ",".join(re.findall('.*PROFILE_CERT_REQUEST.*', logs))
                new_log = request_success_log.format(non_role_user, request_id, default_profile,
                                                     subject)
                assert new_log in profile_cert_req_logs
                log.info("Verified the logs. Found log:\n{}\n".format(new_log))
            else:
                assert 'Request ID: ' in result['stdout']
                assert 'Type: enrollment' in result['stdout']
                assert 'Request Status: rejected' in result['stdout']
                assert 'Operation Result: success' in result['stdout']
                assert 'Reason: Key Parameters 1024,2048,3072,4096 Not Matched' in result['stdout']
                log.info("Successfully run '{}'".format(cert_req))

                request_id_raw = re.findall('Request ID: [\w].*', result['stdout'])
                request_id = request_id_raw[0].split(":")[1].strip()
                log.info("Waiting for request process internally, it will generate logs.")
                time.sleep(5)
                log.info("Checking logs.")
                logs = get_logs(ansible_module)
                profile_cert_req_logs = ",".join(re.findall('.*CERT_REQUEST_PROCESSED.*', logs))
                new_log = request_reject_log.format(non_role_user, request_id, request_id)
                assert new_log in profile_cert_req_logs
                log.info("Verified the logs. Found log:\n{}\n".format(new_log))
        elif key_len == '1321':
            assert 'ERROR: Unable to generate CSR: Command failed. RC: 1' in result['stderr']
        elif result['rc'] >= 1:
            assert 'MissingArgumentException: Missing argument for option: length' in \
                   result['stderr']
        else:
            log.info("Failed to run '{}'".format(cert_req))
            pytest.fail("Failed to run '{}'".format(cert_req))


@pytest.mark.skip(reason="What is attribute encoding?")
def test_pki_client_cert_request_attribute_encoding(ansible_module):
    """
    :Title: Test pki client-cert-request with --attribute-encoding command.
    :Description: test pki client-cert-request --attribute-encoding command
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. command should generates cert request using --attribute-encoding.
    """
    user = 'testuser{}'.format(random.randint(1111, 99999))
    subject = 'UID={},CN=User {}'.format(user, user)
    cert_req = 'pki -d {} -c {} -h {} -P {} -p {} client-cert-request ' \
               '"{}" --attribute-encoding'.format(db2, constants.CLIENT_DIR_PASSWORD,
                                                  constants.MASTER_HOSTNAME,constants.PROTOCOL_UNSECURE,
                                                  constants.CA_HTTP_PORT, subject)
    cert_req_out = ansible_module.command(cert_req)
    for result in cert_req_out.values():
        if result['rc'] == 0:
            assert 'Request ID: ' in result['stdout']
            assert 'Type: enrollment' in result['stdout']
            assert 'Request Status: pending' in result['stdout']
            assert 'Operation Result: success' in result['stdout']
            log.info("Successfully run '{}'".format(cert_req))

            request_id_raw = re.findall('Request ID: [\w].*', result['stdout'])
            request_id = request_id_raw[0].split(":")[1].strip()
            log.info("Checking logs.")
            logs = get_logs(ansible_module)
            profile_cert_req_logs = ",".join(re.findall('.*PROFILE_CERT_REQUEST.*', logs))
            new_log = request_success_log.format(non_role_user, request_id, default_profile,
                                                 subject)
            assert new_log in profile_cert_req_logs
            log.info("Verified the logs. Found log:\n{}\n".format(new_log))
        else:
            log.info("Failed to run '{}'".format(cert_req))
            pytest.fail("Failed to run '{}'".format(cert_req))


@pytest.mark.parametrize('curve', ['', 'nistp256', 'nistp384', 'nistp521',
                                   pytest.param('nistp232', marks=pytest.mark.fail)])
def test_pki_client_cert_request_curve(ansible_module, curve):
    """
    :Title: test pki client-cert-request, Create certificate request with ECC curve.
    :Description: test pki client-cert-request --curve command
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults: Verify whether pki client-cert-request --curve command generates cert request.
    """
    user = 'testuser{}'.format(random.randint(1111, 99999))
    subject = 'UID={},CN=User {}'.format(user, user)
    cert_req = 'pki -d {} -c {} -h {} -P {} -p {} client-cert-request ' \
               '"{}" --algorithm ec --curve {}'.format(db2, constants.CLIENT_DIR_PASSWORD, constants.MASTER_HOSTNAME,
                                                    constants.PROTOCOL_UNSECURE, constants.CA_HTTP_PORT, subject, curve)

    cert_req_out = ansible_module.command(cert_req)
    for result in cert_req_out.values():
        if result['rc'] == 0:
            assert 'Request ID: ' in result['stdout']
            assert 'Type: enrollment' in result['stdout']
            assert 'Request Status: pending' in result['stdout']
            assert 'Operation Result: success' in result['stdout']
            log.info("Successfully run '{}'".format(cert_req))

            request_id_raw = re.findall('Request ID: [\w].*', result['stdout'])
            request_id = request_id_raw[0].split(":")[1].strip()
            log.info("Checking logs.")

            logs = get_logs(ansible_module)
            profile_cert_req_logs = ",".join(re.findall('.*PROFILE_CERT_REQUEST.*', logs))
            new_log = request_success_log.format(non_role_user, request_id, ec_default_profile,
                                                 subject)
            assert new_log in profile_cert_req_logs
            log.info("Verified the logs. Found log:\n{}\n".format(new_log))
        elif curve == 'nistp232':
            assert 'ERROR: Unable to generate CSR: Command failed. RC: 1' in result['stderr']
        elif result['rc'] >= 1:
            assert 'MissingArgumentException: Missing argument for option: curve' in \
                   result['stderr']
        else:
            log.info("Failed to run '{}'".format(cert_req))
            pytest.fail("Failed to run '{}'".format(cert_req))


@pytest.mark.parametrize('bool', ['', 'true', 'false'])
def test_pki_client_cert_request_extractable_true(ansible_module, bool):
    """
    :Title: Test pki client-cert-request --extractable true, to extract the
    certificate from the client database.
    :Description: pki client-cert-request --extractable true, to extract the certificate from
    the client database.
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :ExpectedResults:
        1. pki client-cert-request --extractable command generates cert request.
    """
    user = 'testuser{}'.format(random.randint(1111, 99999))
    subject = 'UID={},CN=User {}'.format(user, user)
    cert_req = 'pki -d {} -c {} -h {} -P {} -p {} client-cert-request "{}" ' \
               '--extractable {}'.format(db2, constants.CLIENT_DIR_PASSWORD, constants.MASTER_HOSTNAME,
                              constants.PROTOCOL_UNSECURE,constants.CA_HTTP_PORT, subject, bool)
    cert_req_out = ansible_module.command(cert_req)
    for result in cert_req_out.values():
        if result['rc'] == 0:
            assert 'Request ID: ' in result['stdout']
            assert 'Type: enrollment' in result['stdout']
            assert 'Request Status: pending' in result['stdout']
            assert 'Operation Result: success' in result['stdout']
            log.info("Successfully run '{}'".format(cert_req))

            request_id_raw = re.findall('Request ID: [\w].*', result['stdout'])
            request_id = request_id_raw[0].split(":")[1].strip()
            log.info("Checking logs.")
            logs = get_logs(ansible_module)
            profile_cert_req_logs = ",".join(re.findall('.*PROFILE_CERT_REQUEST.*', logs))
            new_log = request_success_log.format(non_role_user, request_id, default_profile,
                                                 subject)
            assert new_log in profile_cert_req_logs
            log.info("Verified the logs. Found log:\n{}\n".format(new_log))
        elif result['rc'] >= 1:
            assert 'MissingArgumentException: Missing argument for option: extractable' in \
                   result['stderr']
        else:
            log.info("Failed to run '{}'".format(cert_req))
            pytest.fail("Failed to run '{}'".format(cert_req))


@pytest.mark.fail(reason='BZ-1348835')
def test_pki_client_cert_request_extractable_junk(ansible_module):
    """
    :Title: Test pki client-cert-request --extractable command with junk text
    :Description: test pki client-cert-request --extractable command with junk
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :ExpectedResults:
        1. Verify whether pki client-cert-request --extractable command generates cert request.
    """
    junk = utils.get_random_string(len=10)

    user = 'testuser{}'.format(random.randint(1111, 99999))
    subject = 'UID={},CN=User {}'.format(user, user)
    cert_req = 'pki -d {} -c {} -h {} -P {} -p {} client-cert-request "{}" ' \
               '--extractable {}'.format(db2, constants.CLIENT_DIR_PASSWORD, constants.MASTER_HOSTNAME,
                             constants.PROTOCOL_UNSECURE,constants.CA_HTTP_PORT, subject, junk)
    request_out = ansible_module.command(cert_req)
    for result in request_out.values():
        if result['rc'] >= 1:
            assert "IllegalArgumentException: Invalid extractable parameter: %s" % junk in \
                   result['stderr']
            log.info("Success: Unable to run command with junk extractable option")
        else:
            log.info("Failed to run '{}'".format(cert_req))
            pytest.fail("Failed: Ran client-cert-request command with junk extractable option")


def test_pki_client_cert_request_permanent(ansible_module):
    """
    :Title: Test pki client-cert-request command with permanent option.
    :Description: test pki client-cert-request command with permanent option
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :ExpectedResults:
        1. Verify whether pki client-cert-request --permanent command generates cert request.
    """
    user = 'testuser{}'.format(random.randint(1111, 99999))
    subject = 'UID={},CN=User {}'.format(user, user)
    cert_req = 'pki -d {} -c {} -h {} -P {} -p {} client-cert-request "{}" ' \
               '--permanent'.format(db2, constants.CLIENT_DIR_PASSWORD, constants.MASTER_HOSTNAME,
                                    constants.PROTOCOL_UNSECURE,constants.CA_HTTP_PORT, subject)
    cert_req_out = ansible_module.command(cert_req)
    for result in cert_req_out.values():
        if result['rc'] == 0:
            assert 'Request ID: ' in result['stdout']
            assert 'Type: enrollment' in result['stdout']
            assert 'Request Status: pending' in result['stdout']
            assert 'Operation Result: success' in result['stdout']
            log.info("Successfully run '{}'".format(cert_req))

            request_id_raw = re.findall('Request ID: [\w].*', result['stdout'])
            request_id = request_id_raw[0].split(":")[1].strip()
            log.info("Checking logs.")
            logs = get_logs(ansible_module)
            profile_cert_req_logs = ",".join(re.findall('.*PROFILE_CERT_REQUEST.*', logs))
            new_log = request_success_log.format(non_role_user, request_id, default_profile,
                                                 subject)
            assert new_log in profile_cert_req_logs
            log.info("Verified the logs. Found log:\n{}\n".format(new_log))
        else:
            log.info("Failed to run '{}'".format(cert_req))
            pytest.fail("Failed to run '{}'".format(cert_req))


@pytest.mark.parametrize('boolean', ['true', 'false', 'askdfh32;sdf1'])
def test_pki_client_cert_request_sensitive_true(ansible_module, boolean):
    """
    :Title: Test pki client-cert-request command with sensitive option.
    :Description: test pki client-cert-request command with sensitive option boolean true
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :ExpectedResults:
        1. Verify whether pki client-cert-request --sensitive command generates cert request.
    """
    user = 'testuser{}'.format(random.randint(1111, 99999))
    subject = 'UID={},CN=User {}'.format(user, user)
    cert_req = 'pki -d {} -c {} -h {} -P {} -p {} client-cert-request "{}" ' \
               '--sensitive {}'.format(db2, constants.CLIENT_DIR_PASSWORD, constants.MASTER_HOSTNAME,
                                       constants.PROTOCOL_UNSECURE,constants.CA_HTTP_PORT, subject, boolean)
    cert_req_out = ansible_module.command(cert_req)
    for result in cert_req_out.values():
        if result['rc'] == 0:
            assert 'Request ID: ' in result['stdout']
            assert 'Type: enrollment' in result['stdout']
            assert 'Request Status: pending' in result['stdout']
            assert 'Operation Result: success' in result['stdout']
            log.info("Successfully run '{}'".format(cert_req))

            request_id_raw = re.findall('Request ID: [\w].*', result['stdout'])
            request_id = request_id_raw[0].split(":")[1].strip()
            log.info("Checking logs.")
            logs = get_logs(ansible_module)
            profile_cert_req_logs = ",".join(re.findall('.*PROFILE_CERT_REQUEST.*', logs))
            new_log = request_success_log.format(non_role_user, request_id, default_profile,
                                                 subject)
            assert new_log in profile_cert_req_logs
            log.info("Verified the logs. Found log:\n{}\n".format(new_log))
        elif boolean not in ['true', 'false']:
            if result['rc'] >= 1:
                assert "IllegalArgumentException: Invalid sensitive " \
                       "parameter: {}".format(boolean) in result['stderr']
        else:
            log.info("Failed to run '{}'".format(cert_req))
            pytest.fail("Failed to run '{}'".format(cert_req))


@pytest.mark.parametrize('req_type', ['', 'crmf', 'pkcs10'])
def test_pki_client_cert_request_ssl_ecdh(ansible_module, req_type):
    """
    :Title: Test pki client-cert-request coommand  with ssl-ecdh option.
    :Description: test pki client-cert-request command with ssl-ecdh option
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :ExpectedResults:
        1. Verify whether pki client-cert-request --ssl-ecdh command generates cert request.
    """
    user = 'testuser{}'.format(random.randint(1111, 99999))
    subject = 'UID={},CN=User {}'.format(user, user)
    cert_req = 'pki -d {} -c {} -h {} -P {} -p {} client-cert-request "{}" ' \
               '--ssl-ecdh'.format(db2, constants.CLIENT_DIR_PASSWORD, constants.MASTER_HOSTNAME,
                                   constants.PROTOCOL_UNSECURE,constants.CA_HTTP_PORT, subject)
    if req_type:
        cert_req = cert_req + ' --type {}'.format(req_type)

    cert_req_out = ansible_module.command(cert_req)
    for result in cert_req_out.values():
        if result['rc'] == 0:
            assert 'Request ID: ' in result['stdout']
            assert 'Type: enrollment' in result['stdout']
            assert 'Request Status: pending' in result['stdout']
            assert 'Operation Result: success' in result['stdout']
            log.info("Successfully run '{}'".format(cert_req))

            request_id_raw = re.findall('Request ID: [\w].*', result['stdout'])
            request_id = request_id_raw[0].split(":")[1].strip()
            log.info("Checking logs.")
            logs = get_logs(ansible_module)
            profile_cert_req_logs = ",".join(re.findall('.*PROFILE_CERT_REQUEST.*', logs))
            print(profile_cert_req_logs)
            new_log = request_success_log.format(non_role_user, request_id, default_profile,subject)
            assert new_log in profile_cert_req_logs
            log.info("Verified the logs. Found log:\n{}\n".format(new_log))
        else:
            log.info("Failed to run '{}'".format(cert_req))
            pytest.fail("Failed to run '{}'".format(cert_req))


def test_pki_client_cert_request_with_transport_option(ansible_module):
    """
    :Title: Test pki client-cert-request, create crmf request after extracting transport certificate.
    :Description: test pki client-cert-request command with transport option
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Create nss database
        2. Export kra transport cert from subsystem database
        3. Generate cert request using pki client-cert-request
    :ExpectedResults:
        1. Verify whether pki client-cert-request --transport command generates cert request.
    """
    user = 'testuser{}'.format(random.randint(1111, 99999))
    subject = 'UID={},CN=User {}'.format(user, user)
    transport_name = 'DRM Transport Certificate'
    find_transport_cert = 'pki -P {} -p {} ca-cert-find --name "{}"'.format(constants.PROTOCOL_UNSECURE,constants.CA_HTTP_PORT, transport_name)
    transport_file = '/tmp/transport_crt.pem'
    get_transport = ansible_module.command(find_transport_cert)
    for trans in get_transport.values():
        if trans['rc'] == 0:
            raw_no = re.findall("Serial Number: [\w].*", trans['stdout'])
            transport_cert_id = raw_no[0].split(":")[1].strip()

            ansible_module.command('pki -P {} -p {} ca-cert-show {} '
                                   '--output {}'.format(constants.PROTOCOL_UNSECURE, constants.CA_HTTP_PORT,
                                                        transport_cert_id, transport_file))
    client_cert_req = 'pki -d {} -c {} -P {} -p {} client-cert-request "{}" --profile {} --type {} ' \
                      '--transport {}'.format(constants.NSSDB, constants.CLIENT_DATABASE_PASSWORD,
                                              constants.PROTOCOL_UNSECURE,constants.CA_HTTP_PORT, subject,
                                              'caUserCert', 'crmf',transport_file)
    request_out = ansible_module.command(client_cert_req)
    for result in request_out.values():
        if result['rc'] == 0:
            assert "Request ID:" in result['stdout']
            assert "Type: enrollment" in result['stdout']
            assert "Request Status: pending" in result['stdout']
            assert "Operation Result: success" in result['stdout']
            log.info("Successfully run '{}'".format(client_cert_req))
        else:
            log.info("Failed to run '{}'".format(client_cert_req))
            pytest.fail("Failed to run '{}'".format(client_cert_req))


@pytest.mark.parametrize('req_type', ['', 'crmf', 'pkcs10'])
def test_pki_client_cert_request_with_diff_req_type(ansible_module, req_type):
    """
    :Title: Test pki client-cert-request command, create pkcs10 certificate request.
    :Description: test pki client-cert-request command with type option
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki client-cert-request --type pkcs10 <subject>
    :ExpectedResults:
        1. command generates pkcs10 cert request.
    """

    user = 'testuser{}'.format(random.randint(1111, 99999))
    subject = 'UID={},CN=User {}'.format(user, user)
    cert_req = 'pki -d {} -c {} -h {} -P {} -p {} client-cert-request "{}" ' \
               ' --type {}'.format(db2, constants.CLIENT_DIR_PASSWORD, constants.MASTER_HOSTNAME,
                                   constants.PROTOCOL_UNSECURE,constants.CA_HTTP_PORT, subject, req_type)
    cert_req_out = ansible_module.command(cert_req)
    for result in cert_req_out.values():
        if result['rc'] == 0:
            assert 'Request ID: ' in result['stdout']
            assert 'Type: enrollment' in result['stdout']
            assert 'Request Status: pending' in result['stdout']
            assert 'Operation Result: success' in result['stdout']
            log.info("Successfully run '{}'".format(cert_req))

            request_id_raw = re.findall('Request ID: [\w].*', result['stdout'])
            request_id = request_id_raw[0].split(":")[1].strip()
            log.info("Checking logs.")
            logs = get_logs(ansible_module)
            profile_cert_req_logs = ",".join(re.findall('.*PROFILE_CERT_REQUEST.*', logs))
            new_log = request_success_log.format(non_role_user, request_id, default_profile,
                                                 subject)
            assert new_log in profile_cert_req_logs
            log.info("Verified the logs. Found log:\n{}\n".format(new_log))
        elif req_type == '':
            assert 'MissingArgumentException: Missing argument for option: type' in result['stderr']
        else:
            log.info("Failed to run '{}'".format(cert_req))
            pytest.fail("Failed to run '{}'".format(cert_req))


def test_pki_client_cert_request_without_pop(ansible_module):
    """
    :Title: Test pki client-cert-request command, create crmf certificate request with
    --without-pop.
    :Description: test pki client-cert-request command with without-pop option
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement:
    :Steps:
        1. pki client-cert-request <subject> --type crmf --without-pop
    :ExpectedResults:
        1. command should generates crmf cert request without proof of possession.
    """
    user = 'testuser{}'.format(random.randint(1111, 99999))
    subject = 'UID={},CN=User {}'.format(user, user, user)
    cert_req = 'pki -d {} -c {} -h {} -P {} -p {} client-cert-request "{}" ' \
               '--type crmf --without-pop'.format(db2, constants.CLIENT_DIR_PASSWORD, constants.MASTER_HOSTNAME,
                                                  constants.PROTOCOL_UNSECURE,constants.CA_HTTP_PORT, subject)

    cert_req_out = ansible_module.command(cert_req)
    for result in cert_req_out.values():
        if result['rc'] == 0:
            assert 'Request ID: ' in result['stdout']
            assert 'Type: enrollment' in result['stdout']
            assert 'Request Status: pending' in result['stdout']
            assert 'Operation Result: success' in result['stdout']
            log.info("Successfully run '{}'".format(cert_req))

            request_id_raw = re.findall('Request ID: [\w].*', result['stdout'])
            request_id = request_id_raw[0].split(":")[1].strip()
            log.info("Checking logs.")
            logs = get_logs(ansible_module)
            profile_cert_req_logs = ",".join(re.findall('.*PROFILE_CERT_REQUEST.*', logs))
            new_log = request_success_log.format(non_role_user, request_id, default_profile,
                                                 subject)
            assert new_log in profile_cert_req_logs
            log.info("Verified the logs. Found log:\n{}\n".format(new_log))

        else:
            log.info("Failed to run '{}'".format(cert_req))
            pytest.fail("Failed to run '{}'".format(cert_req))


def test_pki_client_cert_request_user_authentication(ansible_module):
    """
    :Title: Test pki client-cert-request command, expecting to prompt for password.
    :Description: test pki client-cert-request command with username option
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement:
    :Steps:
        1. pki client-cert-request <subject> --username <user> --password
    :ExpectedResults:
        1. Command should promot for password and certificate request should get submitted.
    """
    #cert_req = 'pki -d {} -c {} -p {} client-cert-request '
    user = 'testuser{}'.format(random.randint(1111, 99999))
    subject = 'UID={},CN=User {}'.format(user, user)
    cert_req = 'pki -d {} -c {} -h {} -P {} -p {} client-cert-request "{}" ' \
               '--username {} --password'.format(db2, constants.CLIENT_DIR_PASSWORD, constants.MASTER_HOSTNAME,
                              constants.PROTOCOL_UNSECURE,constants.CA_HTTP_PORT, subject, constants.CA_ADMIN_USERNAME)

    cert_req_out = ansible_module.expect(command=cert_req,
                                         responses={'Password:': constants.CA_PASSWORD})
    for result in cert_req_out.values():
        if result['rc'] == 0:
            assert 'Request ID: ' in result['stdout']
            assert 'Type: enrollment' in result['stdout']
            assert 'Request Status: pending' in result['stdout']
            assert 'Operation Result: success' in result['stdout']
            log.info("Successfully run '{}'".format(cert_req))

            request_id_raw = re.findall('Request ID: [\w].*', result['stdout'])
            request_id = request_id_raw[0].split(":")[1].strip()
            log.info("Checking logs.")
            logs = get_logs(ansible_module)
            profile_cert_req_logs = ",".join(re.findall('.*PROFILE_CERT_REQUEST.*', logs))
            new_log = request_success_log.format(non_role_user, request_id, default_profile,
                                                 subject)
            assert new_log in profile_cert_req_logs
            log.info("Verified the logs. Found log:\n{}\n".format(new_log))

        else:
            log.info("Failed to run '{}'".format(cert_req))
            pytest.fail("Failed to run '{}'".format(cert_req))


@pytest.mark.parametrize('profile', ['AdminCert', 'caCACert', 'caUserCert'])
def test_pki_client_cert_request_with_different_profiles(ansible_module, profile):
    """
    :Title: Client-cert-request with different profiles.
    :Description: client-cert-request with different profiles.
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement:
    :Steps:
        1. pki client-cert-request <subject> --profile AdminCert
        2. pki client-cert-request <subject> --profile caCACert
        3. pki client-cert-request <subject> --profile caUserCert
    :ExpectedResults:
        1. Verify certificate request should get submitted for each profile.
    """
    user = 'testuser{}'.format(random.randint(1111, 99999))
    if profile == 'caCACert':
        userid = 'CA'
        subject = 'CN=CA Signing Certificate,O={}'.format(constants.CA_SECURITY_DOMAIN_NAME)
    else:
        subject = 'UID={},CN=User {}'.format(user, user)
    cert_req = 'pki -d {} -c {} -h {} -P {} -p {} client-cert-request "{}" ' \
               '--profile {}'.format(db2, constants.CLIENT_DIR_PASSWORD, constants.MASTER_HOSTNAME,
                                     constants.PROTOCOL_UNSECURE,constants.CA_HTTP_PORT, subject, profile)
    cert_req_out = ansible_module.command(cert_req)
    for result in cert_req_out.values():
        if result['rc'] == 0:
            assert 'Request ID: ' in result['stdout']
            assert 'Type: enrollment' in result['stdout']
            assert 'Request Status: pending' in result['stdout']
            assert 'Operation Result: success' in result['stdout']
            log.info("Successfully run '{}'".format(cert_req))

            request_id_raw = re.findall('Request ID: [\w].*', result['stdout'])
            request_id = request_id_raw[0].split(":")[1].strip()
            log.info("Checking logs.")
            logs = get_logs(ansible_module)
            profile_cert_req_logs = ",".join(re.findall('.*PROFILE_CERT_REQUEST.*', logs))
            new_log = request_success_log.format(non_role_user, request_id, profile,
                                                 subject)
            assert new_log in profile_cert_req_logs
            log.info("Verified the logs. Found log:\n{}\n".format(new_log))
        else:
            log.info("Failed to run '{}'".format(cert_req))
            pytest.fail("Failed to run '{}'".format(cert_req))


@pytest.mark.parametrize('profile', ['AdminCert', 'caCACert', 'caUserCert'])
def test_pki_client_cert_request_with_different_profiles_with_pkcs10(ansible_module, profile):
    """
    :Title: Client-cert-request with different profiles and type pkcs10
    :Description: test pki client-cert-request command with different profile and type pkcs10
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki client-cert-request <subject> --type pkcs10 --profile AdminCert
        2. pki client-cert-request <subject> --type pkcs10 --profile caCACert
        3. pki client-cert-request <subject> --type pkcs10 --profile caUserCert
    :ExpectedResults:
        1. Command should create certificate request for each profile.
    """
    user = 'testuser{}'.format(random.randint(1111, 99999))
    if profile == 'caCACert':
        userid = 'CA'
        subject = 'CN=CA Signing Certificate,O={}'.format(constants.CA_SECURITY_DOMAIN_NAME)
    else:
        subject = 'UID={},CN=User {}'.format(user, user)
    cert_req = 'pki -d {} -c {} -h {} -P {} -p {} client-cert-request "{}" ' \
               '--profile {} --type pkcs10'.format(db2, constants.CLIENT_DIR_PASSWORD, constants.MASTER_HOSTNAME,
                                        constants.PROTOCOL_UNSECURE,constants.CA_HTTP_PORT, subject, profile)
    cert_req_out = ansible_module.command(cert_req)
    for result in cert_req_out.values():
        if result['rc'] == 0:
            assert 'Request ID: ' in result['stdout']
            assert 'Type: enrollment' in result['stdout']
            assert 'Request Status: pending' in result['stdout']
            assert 'Operation Result: success' in result['stdout']
            log.info("Successfully run '{}'".format(cert_req))

            request_id_raw = re.findall('Request ID: [\w].*', result['stdout'])
            request_id = request_id_raw[0].split(":")[1].strip()
            log.info("Checking logs.")
            logs = get_logs(ansible_module)
            profile_cert_req_logs = ",".join(re.findall('.*PROFILE_CERT_REQUEST.*', logs))
            new_log = request_success_log.format(non_role_user, request_id, profile,
                                                 subject)
            assert new_log in profile_cert_req_logs
            log.info("Verified the logs. Found log:\n{}\n".format(new_log))
        else:
            log.info("Failed to run '{}'".format(cert_req))
            pytest.fail("Failed to run '{}'".format(cert_req))


@pytest.mark.parametrize('profile', ['AdminCert', 'caCACert', 'caUserCert'])
def test_pki_client_cert_request_with_different_profiles_with_crmf(ansible_module, profile):
    """
    :Title: Client-cert-request with different profiles and type crmf
    :Description: test pki client-cert-request command with differnt profiles and type crmf
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki client-cert-request <subject> --type crmf --profile AdminCert
        2. pki client-cert-request <subject> --type crmf --profile caCACert
        3. pki client-cert-request <subject> --type crmf --profile caUserCert
    :ExpectedResults:
        1. Command should create certificate request for each profile.
    """
    user = 'testuser{}'.format(random.randint(1111, 99999))
    if profile == 'caCACert':
        userid = 'CA'
        subject = 'CN=CA Signing Certificate,O={}'.format(constants.CA_SECURITY_DOMAIN_NAME)
    else:
        subject = 'UID={},CN=User {}'.format(user, user)
    cert_req = 'pki -d {} -c {} -h {} -P {} -p {} client-cert-request "{}" ' \
               '--profile {} --type pkcs10'.format(db2, constants.CLIENT_DIR_PASSWORD, constants.MASTER_HOSTNAME,
                                        constants.PROTOCOL_UNSECURE,constants.CA_HTTP_PORT, subject, profile)
    cert_req_out = ansible_module.command(cert_req)
    for result in cert_req_out.values():
        if result['rc'] == 0:
            assert 'Request ID: ' in result['stdout']
            assert 'Type: enrollment' in result['stdout']
            assert 'Request Status: pending' in result['stdout']
            assert 'Operation Result: success' in result['stdout']
            log.info("Successfully run '{}'".format(cert_req))

            request_id_raw = re.findall('Request ID: [\w].*', result['stdout'])
            request_id = request_id_raw[0].split(":")[1].strip()
            log.info("Checking logs.")
            logs = get_logs(ansible_module)
            profile_cert_req_logs = ",".join(re.findall('.*PROFILE_CERT_REQUEST.*', logs))
            new_log = request_success_log.format(non_role_user, request_id, profile,
                                                 subject)
            assert new_log in profile_cert_req_logs
            log.info("Verified the logs. Found log:\n{}\n".format(new_log))
        else:
            log.info("Failed to run '{}'".format(cert_req))
            pytest.fail("Failed to run '{}'".format(cert_req))


def test_bug_1352990_client_cert_request_with_caDirUserCert(ansible_module):
    """
    :Title: Test pki client-cert-request with caDirUserCert profile. BZ: 1352990
    :Description:
        Test pki client-cert-request with caDirUserCert profile.
        To enable caDirUserCert profile make changes in the /var/lib/pki/<instance>/ca/CS.cfg
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands

    :Steps:
        1. configure /var/lib/pki/<instance>/conf/ca/CS.cfg file with following polices.
            auths.instance.UserDirEnrollment.pluginName=UidPwdDirAuth
            auths.instance.UserDirEnrollment.ldap.basedn=dc=example,dc=org
            auths.instance.UserDirEnrollment.ldap.ldapauth.authtype=BasicAuth
            auths.instance.UserDirEnrollment.ldap.ldapauth.bindDN=cn=Directory Manager
            auths.instance.UserDirEnrollment.ldap.ldapauth.bindPWPrompt=internaldb
            auths.instance.UserDirEnrollment.ldap.ldapconn.host=pki1.example.com
            auths.instance.UserDirEnrollment.ldap.ldapconn.port=389
            auths.instance.UserDirEnrollment.ldap.ldapconn.secureConn=false
        2. Restart the CA instance.
        3. Add user in the ldap
        4. Create certificate request against the added user.
        5. Certificate request should be successfully created against the added user.
    """
    if TOPOLOGY == "01":
        instance = 'pki-tomcat'
    else:
        instance = constants.CA_INSTANCE_NAME
    base_dn = "{}-CA".format(instance_name)

    headers = {'Content-type': 'application/json',
               'Accept': 'text/plain'}
    ca_url = 'http://{}:{}/ca/auths'.format(constants.MASTER_HOSTNAME, constants.CA_HTTP_PORT)
    plugin_id = 'UserDirEnrollment'
    data = [('OP_TYPE', 'OP_ADD'),
            ('OP_SCOPE', 'instance'),
            ('RS_ID', plugin_id),
            ('implName', 'UidPwdDirAuth'),
            ('RULENAME', plugin_id),
            ('ldap.ldapconn.host', 'localhost'),
            ('dnpattern', 'UID=*'.format(instance)),
            ('ldapStringAttributes', 'mail'),
            ('ldap.ldapconn.version', '3'),
            ('ldap.ldapconn.port', constants.LDAP_PORT),
            ('ldap.maxConns', '10'),
            ('ldap.basedn', base_dn),
            ('ldap.password', constants.LDAP_PASSWD),
            ('ldap.minConns', '3'),
            ('ldap.ldapconn.secureConn', 'false'),
            ('ldapByteAttributes', 'uid'),
            ]

    search_response = requests.post(ca_url, params=data, headers=headers,
                                    auth=(constants.CA_ADMIN_USERNAME, constants.CA_PASSWORD))

    assert search_response.status_code == 200

    ca_cs_cfg = '/var/lib/pki/{}/conf/ca/CS.cfg'.format(instance)
    policy_file = '/var/lib/pki/{}/ca/profiles/ca/caDirUserCert.cfg'.format(instance)

    bind_dn = constants.LDAP_BIND_DN
    ldap_host = constants.MASTER_HOSTNAME
    ldap_port = constants.LDAP_PORT
    temp_dir = tempfile.mkdtemp(suffix="_test", prefix="pki_")

    enable_prof = 'pki -d {} -c {} -P {} -p {} -n "{}" ca-profile-enable ' \
                  'caDirUserCert'.format(constants.NSSDB, constants.CLIENT_DATABASE_PASSWORD,
                                constants.PROTOCOL_UNSECURE,constants.CA_HTTP_PORT, constants.CA_ADMIN_NICK)

    local_cs_cfg = os.path.join(temp_dir, 'CS.cfg')
    local_policy_file = os.path.join(temp_dir, 'caDirUserCert.cfg')

    ldap_add = 'ldapadd -x -h {} -p {} -D "cn=Directory Manager" -w {} ' \
               '-f /tmp/ldapuser1001'.format(ldap_host, ldap_port, constants.LDAP_PASSWD, base_dn)

    ldap_delete = 'ldapdelete -x -h {} -p {} -D "cn=Directory Manager" ' \
                  '-w {} "uid=testuser1001,ou=People,o={}"'.format(ldap_host, ldap_port, constants.LDAP_PASSWD, base_dn)

    # auth_manager = "auths.instance.UserDirEnrollment.pluginName=UidPwdDirAuth\n" \
    #                "auths.instance.UserDirEnrollment.ldap.basedn={}\n" \
    #                "auths.instance.UserDirEnrollment.ldap.ldapauth.authtype=BasicAuth\n" \
    #                "auths.instance.UserDirEnrollment.ldap.ldapauth.bindDN=cn=Directory " \
    #                "Manager\n" \
    #                "auths.instance.UserDirEnrollment.ldap.ldapauth.bindPWPrompt=internaldb\n" \
    #                "auths.instance.UserDirEnrollment.ldap.ldapconn.host={}\n" \
    #                "auths.instance.UserDirEnrollment.ldap.ldapconn.port={}\n" \
    #                "auths.instance.UserDirEnrollment.ldap.ldapconn.secureConn=false" \
    #                ""
    #
    # log.info("Getting files")
    # ansible_module.fetch(src=ca_cs_cfg, dest=temp_dir, flat=True)
    # ansible_module.fetch(src=policy_file, dest=temp_dir, flat=True)

    # log.info("Backing up CS.cfg file on server.")
    # ansible_module.command('mv {} {}.old'.format(ca_cs_cfg, ca_cs_cfg))
    # ansible_module.command('mv {} {}.old'.format(policy_file, policy_file))

    # log.info("Getting host, port of the ldap server.")
    # if os.path.isfile(local_cs_cfg):
    #     cs_cfg_contents = open(local_cs_cfg, 'r').read()
    #     try:
    #         _ldap_port = re.findall('ldapconn.port=.*', cs_cfg_contents)
    #         ldap_port = _ldap_port[0].split("=")[1].strip()
    #         _ldap_host = re.findall('ldapconn.host=.*', cs_cfg_contents)
    #         ldap_host = _ldap_host[0].split("=")[1].strip()
    #         # base_dn = ",".join(["dc=%s" % i for i in ldap_host.split(".")[1:]])
    #         base_dn = constants.LDAP_BASE_DN
    #         log.info("Adding ldap auth manager to cs.cfg file.")
    #         cs_cfg_contents += auth_manager.format(base_dn, ldap_host, ldap_port)
    #         log.info("Writing CS.cfg file.")
    #         ansible_module.copy(dest=ca_cs_cfg, content=cs_cfg_contents, force=True)
    #     except Exception as e:
    #         log.info(e)
    # else:
    #     log.error("Failed to fetch file '{}'".format(ca_cs_cfg))
    #     pytest.fail("Failed to copy file.")
    ldap_user = "dn: uid=testuser1001,ou=People,o={}\n" \
                "objectClass: person\n" \
                "objectClass: organizationalPerson\n" \
                "objectClass: inetOrgPerson\n" \
                "uid: testuser1001\n" \
                "cn: Test User\n" \
                "sn: User\n" \
                "userPassword: {}".format(base_dn, constants.CA_PASSWORD)

    ansible_module.copy(dest='/tmp/ldapuser1001', content=ldap_user)
    cmd = ansible_module.command(ldap_add)
    if os.path.isfile(local_policy_file):
        policy_file_contents = open(local_policy_file).read()
        re.sub(policy_file_contents, "policyset.userCertSet.2.default.params.range=.*",
               "policyset.userCertSet.2.default.params.range=30")

        ansible_module.copy(dest=policy_file, content=policy_file_contents, flat=True)

    ansible_module.command('systemctl restart pki-tomcatd@{}'.format(instance))
    ansible_module.command(enable_prof)
    profile_cmd = 'pki -d {} -P {} -p {} -c {} client-cert-request --profile caDirUserCert ' \
                  '--username testuser1001 --password'.format(constants.NSSDB,
                                                              constants.PROTOCOL_UNSECURE,
                                                              constants.CA_HTTP_PORT,
                                                              constants.CLIENT_DATABASE_PASSWORD)

    profile_out = ansible_module.expect(command=profile_cmd,
                                        responses={'Password:': constants.CA_PASSWORD})
    for result in profile_out.values():
        if result['rc'] == 0:
            assert "Request ID:" in result['stdout']
            assert "Type: enrollment" in result['stdout']
            assert "Request Status: complete" in result['stdout']
            assert "Operation Result: success" in result['stdout']
            assert "Certificate ID:" in result['stdout']

            log.info("Successfully verified bug 1352990.")

        if result['rc'] >= 1:
            log.info("Failed to verify bug 1352990.")
            # pytest.fail("Failed to verify bug 1352990.")
    data_del = [('OP_TYPE', 'OP_DELETE'),
                ('OP_SCOPE', 'instance'),
                ('RS_ID', plugin_id)]

    search_response = requests.post(ca_url, params=data_del, headers=headers,
                                    auth=(constants.CA_ADMIN_USERNAME, constants.CA_PASSWORD))
    search_response.encoding = 'utf-8'
    log.info("Removing ldap user.")
    ansible_module.command(ldap_delete)
    ansible_module.command('rm -rf {}'.format(temp_dir))
    log.info("Restoring CS.cfg file and Policy file.")
    ansible_module.command('mv {}.old {}'.format(ca_cs_cfg, ca_cs_cfg))
    ansible_module.command('mv {}.old {}'.format(policy_file, policy_file))
    log.info("Restarting Instance.")
    ansible_module.command('systemctl restart pki-tomcatd@{} '.format(instance))


def test_pki_client_cert_request_with_i18n_character(ansible_module):
    """
    :id: 6aaf281e-6a45-48a0-8de4-4f3816351874
    :Title: Test pki client-cert-request, create certificate request with i18n
    :Description: test pki client-cert-request command with i18n
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d <nssdb> -c SECret.123 -p <secure_port> client-cert-request 'uid=i18n character'
    :ExpectedResults: Verify whether pki client-cert-request command generates cert request.
    """
    user = "Örjan Äke"
    subject = 'UID={}, CN={}'.format(user, user)
    cert_req = ansible_module.pki(cli='client-cert-request',
                                      nssdb=db2,
                                      dbpassword=constants.CLIENT_DIR_PASSWORD,
                                      port=constants.CA_HTTPS_PORT,
                                      protocol='https',
                                      certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                      extra_args='"{}"'.format(subject))
    for result in cert_req.values():
        if result['rc'] == 0:
            request_id_raw = re.findall('Request ID: [\w].*', result['stdout'])
            request_id = request_id_raw[0].split(":")[1].strip()
            assert 'Request ID: {}'.format(request_id) in result['stdout']
            assert 'Type: enrollment' in result['stdout']
            assert 'Request Status: pending' in result['stdout']
            assert 'Operation Result: success' in result['stdout']
            log.info("Successfully run '{}'".format(cert_req))
        else:
            log.error("Failed to run '{}'".format(cert_req))
            pytest.fail("Failed to run '{}'".format(cert_req))
