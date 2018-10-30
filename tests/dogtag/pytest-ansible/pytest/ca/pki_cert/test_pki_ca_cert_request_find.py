#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI USER-CERT CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki user commands needs to be tested:
#   pki user-cert
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
import pytest
import re
import sys

from pki.testlib.common.utils import UserOperations

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

user_op = UserOperations(nssdb=constants.NSSDB)
log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
topology = constants.CA_INSTANCE_NAME.split("-")[-1]
cmd = 'ca-cert-request-find'

status = ['pending', 'cancel', 'reject', 'approve']
tenses = {'cancel': 'canceled',
          'pending': 'pending',
          'reject': 'rejected',
          'approve': 'complete'}


@pytest.mark.parametrize('subcmd', ['', '--help'])
def test_pki_ca_cert_request_find_help(ansible_module, subcmd):
    """
    :Title: Test pki ca-cert-request-find with '' and --help command.
    :Description: pki ca-cert-request-find with '' and --help command should show requests and
                  and help message respectively.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki ca-cert-request-find --help
        2. pki ca-cert-request-find
    :Expectedresults:
        1. It should show the ca-cert-request-find help message.
        2. It should show the certificate requests.
    """
    help_out = ansible_module.command('pki -p {} {} {}'.format(constants.CA_HTTP_PORT, cmd, subcmd))

    for result in help_out.values():
        log.info("Running : {}".format(result['cmd']))
        if result['rc'] == 0:
            if subcmd == '--help':
                assert 'usage: {} [OPTIONS...]'.format(cmd) in result['stdout']
                assert '--help                      Show help options' in result['stdout']
                assert '--maxResults <maxResults>   Maximum number of results' in result['stdout']
                assert '--size <size>               Page size' in result['stdout']
                assert '--start <start>             Page start' in result['stdout']
                assert '--status <status>           Request status (pending, cancelled,' in result[
                    'stdout']
                assert 'rejected, complete, all)' in result['stdout']
                assert '--timeout <maxTime>         Search timeout' in result['stdout']
                assert '--type <type>               Request type (enrollment, renewal,' in result[
                    'stdout']
                assert 'revocation, all)' in result['stdout']
            else:
                assert "entries matched" in result['stdout']
                assert 'Request ID:' in result['stdout']
                assert 'Type: ' in result['stdout']
                assert 'Request Status: ' in result['stdout']
                assert 'Operation Result: ' in result['stdout']
                log.info("Successfully run pki {} {}".format(cmd, subcmd))
        else:
            assert "PKIException: Unauthorized" in result['stderr']
            log.info("Successfully run pki {} {}".format(cmd, subcmd))


@pytest.mark.parametrize('subcmd', ['pending', 'cancel','reject', 'approve'])
def test_pki_ca_cert_request_find_with_different_status(ansible_module, subcmd):
    """
    :Title: Test pki ca-cert-request-find with diff status, like: pending, cancel, reject, approve.
    :Description: This test will show all the certificate request which are matching with the
                  passed status.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Submit the certificate request.
        2. Reject the certificate request, and run pki ca-cert-request-find --status reject
        3. Follow step 1, and run pki ca-cert-request-find --status pending
        4. Follow step 1 and Cancel the request, and run pki ca-cert-request-find --status cancel
        5. Follow step 1 and Approve the request, and run pki ca-cert-request-find --status
        complete.
    :Expectedresults:
        1. Request should be successfully submitted.
        2. It should show the rejected certificate requests.
        3. It should show the pending certificate requests.
        4. It should show the canceled certificate requests.
        5. It should show the approved certificate requests.
    """

    userid = 'testuser2'
    subject = '/UID={},CN={}'.format(userid, userid)
    req_file = '/tmp/{}.req'.format(userid)
    request_id = None
    msg = ''
    gen_key = ansible_module.command('openssl genrsa -out /tmp/{}.key 2048'.format(userid))
    for res in gen_key.values():
        assert res['rc'] == 0
    gen_req = ansible_module.command('openssl req -new -sha512 -key /tmp/{}.key '
                                     '-out {} -subj "{}"'.format(userid, req_file, subject))
    for res in gen_req.values():
        assert res['rc'] == 0

    submit_request = ansible_module.pki(cli='ca-cert-request-submit',
                                        nssdb=constants.NSSDB,
                                        dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                        port=constants.CA_HTTP_PORT,
                                        extra_args=" --csr-file {} --subject {} --profile "
                                                   "caUserCert".format(req_file,
                                                                       subject.replace("/", '')))

    for result in submit_request.values():
        log.info("Running : {}".format(result['cmd']))
        if result['rc'] == 0:
            assert 'Submitted certificate request' in result['stdout']
            assert 'Request ID:' in result['stdout']
            assert 'Type: enrollment' in result['stdout']
            assert 'Request Status: pending' in result['stdout']
            assert 'Operation Result: success' in result['stdout']
            log.info("Successfully submitted the certificate request. ")
            request_id = re.search('Request ID: [\w]*', result['stdout']).group().encode('utf-8')
            request_id = request_id.split(":")[1].strip()
            log.info("Request Id : {}".format(request_id))
            if subcmd in ['approve']:
                msg = 'Approved'
            elif subcmd == 'cancel':
                msg = tenses[subcmd]

            if subcmd != 'pending':
                request_out = ansible_module.pki(cli='cert-request-review',
                                                 nssdb=constants.NSSDB,
                                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                                 port=constants.CA_HTTP_PORT,
                                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                                 extra_args=' --action {} {}'.format(subcmd,
                                                                                     request_id))
                for result1 in request_out.values():
                    log.info("Running : {}".format(result1['cmd']))
                    if result1['rc'] == 0:
                        assert '{} certificate request {}'.format(msg.title(),
                                                                  request_id) in result1['stdout']
                        assert 'Request ID: {}'.format(request_id) in result1['stdout']
                        assert 'Type: enrollment' in result1['stdout']
                        assert 'Request Status: {}'.format(tenses[subcmd]) in result1['stdout']
                        assert 'Operation Result: success' in result1['stdout']
                        log.info("Successfully {} certificate request".format(tenses[subcmd]))
                    else:
                        log.error("Failed to run pki cert-request-review "
                                  "--action {} {}".format(subcmd, request_id))
                        pytest.xfail("Failed to run pki cert-request-review "
                                     "--action {} {}".format(subcmd, request_id))
    st = tenses.get(subcmd, subcmd)
    find_req = ansible_module.pki(cli=cmd,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  port=constants.CA_HTTP_PORT,
                                  certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                  extra_args=' --status {} --size 1000'.format(st))
    for result in find_req.values():
        log.info("Running : {}".format(result['cmd']))
        if result['rc'] == 0:
            assert "entries matched" in result['stdout']
            if '0 entries matched' not in result['stdout']:
                assert 'Request ID: {}'.format(request_id) in result['stdout']
                assert 'Type: ' in result['stdout']
                assert 'Request Status: {}'.format(st) in result['stdout']
                assert 'Operation Result: ' in result['stdout']
                log.info("Successfully run {}".format(result['cmd']))
            else:
                log.info("0 entries matched")
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            log.info(result['stdout'])
            log.info(result['stderr'])
            pytest.xfail("Failed to run pki {} --status {}".format(cmd, st))


def test_pki_ca_cert_request_find_with_status_all(ansible_module):
    """
    :Title: Test pki ca-cert-request-find with status all.
    :Description: This test should show all the certificates.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Submit the certificate request.
        2. Follow step 1, approve the certificate request.
        3. Follow step 1, reject the certificate request.
        4. Follow step 1, cancel the certificate request.
        5. Follow step 1
        6. Run pki ca-cert-request-find --status all
            
    :Expectedresults:
        1. It should show all the certificate request which made earlier.
    """
    find_req = ansible_module.pki(cli=cmd,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  port=constants.CA_HTTP_PORT,
                                  certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                  extra_args=' --status all --size 1000')
    for result in find_req.values():
        log.info("Running : {}".format(result['cmd']))
        if result['rc'] == 0:
            assert "entries matched" in result['stdout']
            if '0 entries matched' not in result['stdout']:
                assert 'Request ID:' in result['stdout']
                assert 'Type: ' in result['stdout']
                assert 'Request Status: ' in result['stdout']
                assert 'Operation Result: ' in result['stdout']
                log.info("Successfully run pki {} --status all --size 1000".format(cmd))
            else:
                log.info("0 entries matched")
        else:
            log.error("Failed to run pki {} --status all --size 1000")
            pytest.xfail("Failed to run pki {} --status {}".format(cmd, 'all'))


@pytest.mark.parametrize('max_results', ['1', '1000'])
@pytest.mark.parametrize('st', status)
def test_pki_ca_cert_request_find_with_status_maxResult(ansible_module, max_results, st):
    """
    :Title: Test pki ca-cert-request-find with status and max_result
    :Description: This test will test the certificate request listing with the status and
                  max results
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-cert-request-find with --status approved --maxResults 1 or 1000
        2. Run pki ca-cert-request-find with --status cancel --maxResults 1 or 1000
        3. Run pki ca-cert-request-find with --status reject --maxResults 1 or 1000
        4. Run pki ca-cert-request-find with --status pending --maxResults 1 or 1000
    :Expectedresults:
        1. It should show all the approved certificate requests as per maxResult
        2. It should show all the cancled certificate requests as per maxResult
        3. It should show all the rejected certificate requests as per maxResult
        4. It should show all the pending certificate requests as per maxResult
    """
    max_result = ansible_module.pki(cli=cmd,
                                    nssdb=constants.NSSDB,
                                    dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                    port=constants.CA_HTTP_PORT,
                                    certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                    extra_args='--status {} --maxResults {}'.format(tenses[st],
                                                                                    max_results))
    for result in max_result.values():
        log.info("Running : {}".format(result['cmd']))
        if result['rc'] == 0:
            assert 'entries matched' in result['stdout']
            if '0 entries matched' not in result['stdout']:
                assert 'Request ID:' in result['stdout']
                assert 'Type:' in result['stdout']
                assert 'Request Status:' in result['stdout']
                for i in status:
                    if i != st:
                        assert 'Request Status: {}'.format(tenses[i]) not in result['stdout']
                assert 'Operation Result: ' in result['stdout']
                assert 'Number of entries returned' in result['stdout']
                log.info("Successfully run pki {} --status {} --maxResults {} ".format(cmd,
                                                                                       tenses[st],
                                                                                       max_results))
        else:
            log.error("Failed to run pki {} --status {} --maxSize {}".format(cmd, st, max_results))
            pytest.xfail("Failed to run pki {} --status {} --maxSize {}".format(cmd, st,
                                                                                max_results))


@pytest.mark.parametrize('r_type', ['enrollment', 'renewal', 'revocation'])
@pytest.mark.parametrize('st', status)
def test_pki_ca_cert_request_find_with_type_and_status(ansible_module, r_type, st):
    """
    :Title: Test pki ca-cert-request-find with type and status
    :Description: This test will check certificate request listing as per the type and status.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-certificate-request-find --type enrollment --status pending
        2. Run pki ca-certificate-request-find --type enrollment --status complete
        3. Run pki ca-certificate-request-find --type enrollment --status reject
        4. Run pki ca-certificate-request-find --type enrollment --status cancel
        5. Run pki ca-certificate-request-find --type renewal --status pending
        6. Run pki ca-certificate-request-find --type renewal --status complete
        7. Run pki ca-certificate-request-find --type renewal --status reject
        8. Run pki ca-certificate-request-find --type renewal --status cancel
        9. Run pki ca-certificate-request-find --type revocation --status pending
        10. Run pki ca-certificate-request-find --type revocation --status complete
        11. Run pki ca-certificate-request-find --type revocation --status reject
        12. Run pki ca-certificate-request-find --type revocation --status cancel
    :Expectedresults:
        1. It will show all the enrollment certificate request with pending status.
        2. It will show all the enrollment certificate request with complete status.
        3. It will show all the enrollment certificate request with reject status.
        4. It will show all the enrollment certificate request with cancel status.
        5. It will show all the renewal certificate request with pending status.
        6. It will show all the renewal certificate request with complete status.
        7. It will show all the renewal certificate request with reject status.
        8. It will show all the renewal certificate request with cancel status.
        9. It will show all the revocation certificate request with pending status.
        10. It will show all the revocation certificate request with complete status.
        11. It will show all the revocation certificate request with reject status.
        12. It will show all the revocation certificate request with cancel status.
    """
    type_and_status = ansible_module.pki(cli=cmd,
                                         nssdb=constants.NSSDB,
                                         dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                         port=constants.CA_HTTP_PORT,
                                         certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                         extra_args=" --type {} --status {}".format(r_type, st))

    for result in type_and_status.values():
        log.info("Running : {}".format(result['cmd']))
        if result['rc'] == 0:
            assert 'entries matched' in result['stdout']
            if '0 entries matched' not in result['stdout']:
                assert 'Request ID:' in result['stdout']
                assert 'Type:' in result['stdout']
                assert 'Request Status:' in result['stdout']
                for i in status:
                    if i != st:
                        assert 'Request Status: {}'.format(tenses[i]) not in result['stdout']
                assert 'Operation Result: ' in result['stdout']
                assert 'Number of entries returned' in result['stdout']
                log.info("Successfully run pki {} --type {} --status {}".format(cmd, r_type, st))
        else:
            log.error("Failed to run pki {} --type {} --status {}".format(cmd, r_type, st))
            pytest.xfail("Failed to run pki ca-cert-request-show with "
                         "--type {} --status {}".format(r_type, st))


@pytest.mark.parametrize('start', [5, pytest.mark.xfail(-5), 'xe2at', ''])
def test_pki_ca_cert_request_find_with_start_option(ansible_module, start):
    """
    :Title: Test pki ca-cert-request-find with start option.
    :Description: Run pki ca-cert-request-find command with start option and pass different
                  arguments to it.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-cert-request-find --start 5
        2. Run pki ca-cert-request-find --start -5
        3. Run pki ca-cert-request-find --start 'xe2at'
        4. Run pki ca-cert-request-find --start ''
    :Expectedresults:
        1. It will return entry of the requests from 5 to 24.
        2. It will not return any entry.
        3. It will throw an exception.
        4. It will throw an exception.
    """
    if start == 5 or start == -5:
        error = 'Number of entries returned 20'
    elif start == 'xe2at':
        error = 'NumberFormatException: For input string: "xe2at"'
    elif start == '':
        error = 'MissingArgumentException: Missing argument for option: start'

    req_find = ansible_module.pki(cli=cmd,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  port=constants.CA_HTTP_PORT,
                                  certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                  extra_args=" --start {} ".format(start))

    for result in req_find.values():
        log.info("Running : {}".format(result['cmd']))
        if result['rc'] == 0:
            assert error in result['stdout']
            log.info("Successfully run pki {} --start {}".format(cmd, start))
        else:
            assert error in result['stderr']


@pytest.mark.parametrize('maxr', [pytest.mark.xfail(5), pytest.mark.xfail(-5),
                                  'xe2at', '', '39493840234'])
def test_pki_ca_cert_request_find_with_maxresult_option(ansible_module, maxr):
    """
    :Title: Test pki ca-cert-request-find with maxResult option.
    :Description: Run pki ca-cert-request-find command with maxResult option and pass different
                  arguments to it.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-cert-request-find --maxResult 5
        2. Run pki ca-cert-request-find --maxResult -5
        3. Run pki ca-cert-request-find --maxResult 'xe2at'
        4. Run pki ca-cert-request-find --maxResult ''
        5. Run pki ca-cert-request-find --maxResult '39493840234'
    :Expectedresults:
        1. It will return entry of the requests from 5 to 24.
        2. It will not return any entry.
        3. It will throw an exception.
        4. It will throw an exception.
        5. It will throw an exception.
    """
    error = ''
    if maxr == 5 or maxr == -5:
        error = 'Number of entries returned 20'
    elif maxr == 'xe2at':
        error = 'NumberFormatException: For input string: "xe2at"'
    elif maxr == '':
        error = 'MissingArgumentException: Missing argument for option: maxResult'
    elif maxr == '':
        error = 'NumberFormatException: For input string: "39493840234"'
    req_find = ansible_module.pki(cli=cmd,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  port=constants.CA_HTTP_PORT,
                                  certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                  extra_args=" --maxResults {} ".format(maxr))

    for result in req_find.values():
        log.info("Running : {}".format(result['cmd']))
        if result['rc'] == 0:
            assert error in result['stdout']
            log.info("Successfully run pki {} --maxResults {}".format(cmd, maxr))
        else:
            assert error in result['stderr']


@pytest.mark.parametrize('size', [5, pytest.mark.xfail(-5), 'xe2at', '', '39493840234'])
def test_pki_ca_cert_request_find_with_size_option(ansible_module, size):
    """
    :Title: Test pki ca-cert-request-find with size option.
    :Description: Run pki ca-cert-request-find command with size option and pass different
                  arguments to it.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-cert-request-find --size 5
        2. Run pki ca-cert-request-find --size -5
        3. Run pki ca-cert-request-find --size 'xe2at'
        4. Run pki ca-cert-request-find --size ''
        5. Run pki ca-cert-request-find --size '39493840234'
    :Expectedresults:
        1. It will return entry of the requests from 5 to 24.
        2. It will not return any entry.
        3. It will throw an exception.
        4. It will throw an exception.
        5. It will throw an exception.
    """
    error = ''
    if size == 5:
        error = 'Number of entries returned 5'
    elif size == -5:
        error = 'Number of entries returned 20'
    elif size == 'xe2at':
        error = 'NumberFormatException: For input string: "xe2at"'
    elif size == '':
        error = 'MissingArgumentException: Missing argument for option: size'
    elif size == '':
        error = 'NumberFormatException: For input string: "39493840234"'
    req_find = ansible_module.pki(cli=cmd,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  port=constants.CA_HTTP_PORT,
                                  certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                  extra_args=" --size {} ".format(size))

    for result in req_find.values():
        log.info("Running : {}".format(result['cmd']))
        if result['rc'] == 0:
            assert error in result['stdout']
            log.info("Successfully run pki {} --size {}".format(cmd, size))
        else:
            assert error in result['stderr']


@pytest.mark.parametrize('cert', ['CA_AdminE', 'CA_AgentE', 'CA_AuditE'])
def test_pki_ca_cert_request_find_with_expired_certificates(ansible_module, cert):
    """
    :Title: Test pki ca-cert-request-find command with expired certificate.
    :Description: pki ca-cert-request-find command with expired certificate.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Run pki -n CA_AdminE ca-cert-find
        2. Run pki -n CA_AgentE ca-cert-find
        3. Run pki -n CA_AuditE ca-cert-find
    :Expectedresults:
        1. All the commands will throw SSL Alert. Certificate Expired.
    """
    req_find = ansible_module.pki(cli=cmd,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  port=constants.CA_HTTP_PORT,
                                  certnick='"{}"'.format(cert))

    for result in req_find.values():
        log.info("Running : {}".format(result['cmd']))
        if result['rc'] >= 1:
            assert 'FATAL: SSL alert received: CERTIFICATE_EXPIRED' in result['stderr']
            assert 'IOException: SocketException cannot write on socket' in result['stderr']
            log.info("Successfully run pki -n {} {}".format(cert, cmd))
        else:
            log.error("Failed to run {}".format(result['cmd']))
            pytest.xfail()


@pytest.mark.parametrize('cert,error', [('CA_AdminV', 'ForbiddenException: Authorization Error'),
                                        ('CA_AuditV', 'ForbiddenException: Authorization Error'),
                                        ('CA_AgentV', 'Number of entries returned 20'), ])
def test_pki_ca_cert_request_find_with_different_valid_certs(ansible_module, cert, error):
    """
    :Title: Test pki ca-cert-request-find with different valid certificates
    :Description: Test pki ca-cert-request-find with different valid certificates.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Run pki -n CA_AdminV ca-cert-request-find
        2. Run pki -n CA_AuditV ca-cert-request-find
        3. Run pki -n CA_AgentV ca-cert-request-find
    :Expectedresults:
        1. Will throw an ForbiddenExeption.
        2. Will throw and ForbiddenExeption.
        3. Will Show entries.
    """
    req_find = ansible_module.pki(cli=cmd,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  port=constants.CA_HTTP_PORT,
                                  certnick='"{}"'.format(cert))

    for result in req_find.values():
        log.info("Running : {}".format(result['cmd']))
        if result['rc'] == 0:
            assert error in result['stdout']
            log.info("Successfully run pki -n {} {}".format(cert, cmd))
        else:
            assert error in result['stderr']


def test_pki_ca_cert_request_find_with_normal_user(ansible_module):
    """
    :Title: Test pki ca-cert-request-find using normal user.
    :Description: Test pki ca-cert-request-find using normal user. It will throw an exception.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Add user.
        2. Issue certificate to the user.
        3. Add the certificate to the user.
        4. Import the certificate to the user database.
    :Expectedresults:
        1. It should not able to list the certificate requests.
    """

    user = 'testuser03'
    fullName = 'Test User 03'
    subject = 'UID={},CN={}'.format(user, fullName)
    user_op.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    log.info("Added user {}".format(user))
    cert_id = user_op.process_certificate_request(ansible_module, subject=subject)
    log.info("Generated certificate for the user {}, Cert ID: {}".format(user, cert_id))
    add_cert_to_user = ansible_module.pki(cli='ca-user-cert-add',
                                          nssdb=constants.NSSDB,
                                          dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                          port=constants.CA_HTTP_PORT,
                                          certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                          extra_args='{} --serial {}'.format(user, cert_id))

    for res in add_cert_to_user.values():
        log.info("Running : {}".format(res['cmd']))
        if res['rc'] == 0:
            assert 'Added certificate' in res['stdout']
            log.info("Added certificate to the user.")
        else:
            log.error("Failed to add certificate to the user.")
            log.info(res['stderr'])
            pytest.xfail()
    import_cert_to_db = ansible_module.pki(cli='client-cert-import',
                                           nssdb=constants.NSSDB,
                                           dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                           port=constants.CA_HTTP_PORT,
                                           certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                           extra_args='{} --serial {}'.format(user, cert_id))

    for res in import_cert_to_db.values():
        log.info("Running : {}".format(res['cmd']))
        if res['rc'] == 0:
            assert 'Imported certificate "{}"'.format(user) in res['stdout']
            log.info("Certificate imported to client db.")
        else:
            log.error("Failed to import certificate to client db.")
            pytest.xfail()
    cert_req_find = ansible_module.pki(cli=cmd,
                                       nssdb=constants.NSSDB,
                                       dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                       port=constants.CA_HTTP_PORT,
                                       certnick='"{}"'.format(user))

    for res in cert_req_find.values():
        log.info("Running : {}".format(res['cmd']))
        if res['rc'] != 0:
            assert 'ForbiddenException: Authorization Error' in res['stderr']
            log.info("Successfully run pki -n {} {}".format(user, cmd))
        else:
            log.error("Failed to run pki -n {} {}".format(user, cmd))
            pytest.xfail()
    remove_cert = ansible_module.pki(cli='client-cert-del',
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='{}'.format(user))

    for res in remove_cert.values():
        log.info("Running : {}".format(res['cmd']))
        if res['rc'] == 0:
            assert 'Removed certificate "{}"'.format(user) in res['stdout']
            log.info("Successfully removed certificate '{}'".format(user))
        else:
            log.error("Failed to remove cert {} form client db".format(user))
            pytest.xfail()
    user_op.remove_user(ansible_module, user)
    log.info("Removed user {}".format(user))
