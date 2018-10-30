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
import random

import os
import pytest
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
cmd = 'ca-cert-hold'


@pytest.mark.parametrize('subcmd', ('', '--help'))
def test_pki_cert_hold_help(ansible_module, subcmd):
    """
    :Title: Test pki ca-cert-hold with '' and --help argument
    :Description:
        pki ca-cert-hold with argument '' expected to show the error message and
        with --help message it expected to show the help message.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-cert-hold
        2. Run pki ca-cert-hold --help
    :Expectedresults:
        1. Expected to show the error message Error: Missing Serial Number.
        2. Expected to show the help message.
    """
    help_out = ansible_module.command('pki {} {}'.format(cmd, subcmd))
    for result in help_out.values():
        log.info("Running : {}".format(result['cmd']))
        if result['rc'] == 0:
            assert 'usage: {} <Serial Number> [OPTIONS...]'.format(cmd) in result['stdout']
            assert '--comments <comments>   Comments' in result['stdout']
            assert '--force                 Force' in result['stdout']
            assert '--help                  Show help options' in result['stdout']
            log.info("Successfully run pki {} {}".format(cmd, subcmd))
        else:
            assert 'Error: Missing Serial Number.' in result['stderr']
            log.info("Successfully run pki {} {}".format(cmd, subcmd))


def test_pki_cert_hold_using_agent_cert(ansible_module):
    """
    :Title: Test pki ca-cert-hold using valid Agent Certificate
    :Description: Pki ca-cert-hold using valid Agent Certificate able to hold the certificate.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Add the user.
        2. Issue the certificate request.
        3. Approve the certificate request.
        4. run pki -n CA_AgentV ca-cert-hold <cert_id>
           It should ask for (Y/N) and answer should be Y.
    :Expectedresults:
        1. User should get added.
        2. Certificate request should be issued and submitted to the CA.
        3. Get the certificate id after the approval of the request id.
        4. It should put the certificate on hold.
    """
    userid = 'testuser{}'.format(random.randint(1111, 9999999))
    subject = 'UID={},E={}@example.org,CN={},OU=Engineering,O=Example.Org'.format(userid, userid,
                                                                                  userid)
    cert_id = user_op.process_certificate_request(ansible_module, subject=subject)
    log.info("Generated certificate with Cert ID: {}".format(cert_id))
    command = 'pki -d {} -c {} -p {} -n "{}" ' \
              '{} {}'.format(constants.NSSDB, constants.CLIENT_DATABASE_PASSWORD,
                             constants.CA_HTTP_PORT, 'CA_AgentV', cmd, cert_id)
    hold_out = ansible_module.expect(command=command,
                                     responses={"Are you sure \(Y\/N\)?": "Y"})
    for result in hold_out.values():
        if result['rc'] == 0:
            assert 'Placed certificate "{}" on-hold'.format(cert_id) in result['stdout']
            assert 'Serial Number: {}'.format(cert_id) in result['stdout']
            assert 'Subject DN: {}'.format(subject) in result['stdout']
            assert 'Issuer DN: ' in result['stdout']
            assert 'Status: REVOKED' in result['stdout']
            assert 'Not Valid Before:' in result['stdout']
            assert 'Not Valid After:' in result['stdout']
            assert 'Revoked On:' in result['stdout']
            assert 'Revoked By: CA_AgentV' in result['stdout']
        else:
            log.error("Failed to run {}".format(cmd))
            log.info(result['stderr'])
            pytest.xfail()


def test_pki_cert_hold_using_agent_cert_and_with_comment(ansible_module):
    """
    :Title: Test pki ca-cert-hold with valid Agent Cert and with comment.
    :Description: This test should put certificate on hold with the comment message.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Add the user.
        2. Issue the certificate request.
        3. Approve the certificate request.
        4. Run pki -n CA_AgentV ca-cert-hold <cert_id> --comment "Testing comment"
    :Expectedresults:
        1. User should get added.
        2. Certificate should be issued.
        3. Certificate request should get approved and get the cert id.
        4. Certificate should put on the hold with the comment "Testing Comment"
    """
    userid = 'testuser{}'.format(random.randint(1111, 9999999))
    subject = 'UID={},E={}@example.org,CN={},OU=Engineering,O=Example.Org'.format(userid, userid,
                                                                                  userid)
    cert_id = user_op.process_certificate_request(ansible_module, subject=subject)
    log.info("Generated certificate with the cert ID: {}".format(cert_id))

    command = 'pki -d {} -c {} -p {} -n "{}" ' \
              '{} {} {}'.format(constants.NSSDB, constants.CLIENT_DATABASE_PASSWORD,
                                constants.CA_HTTP_PORT, 'CA_AgentV', cmd, cert_id,
                                '--comments "Test Comment"')

    hold_out = ansible_module.expect(command=command,
                                     responses={"Are you sure \(Y\/N\)?": "Y"})
    for result in hold_out.values():
        if result['rc'] == 0:
            assert 'Placed certificate "{}" on-hold'.format(cert_id) in result['stdout']
            assert 'Serial Number: {}'.format(cert_id) in result['stdout']
            assert 'Subject DN: {}'.format(subject) in result['stdout']
            assert 'Issuer DN: ' in result['stdout']
            assert 'Status: REVOKED' in result['stdout']
            assert 'Not Valid Before:' in result['stdout']
            assert 'Not Valid After:' in result['stdout']
            assert 'Revoked On:' in result['stdout']
            assert 'Revoked By: CA_AgentV' in result['stdout']
            log.info("Successfully run {}".format(command))
        else:
            log.error("Failed to run {}".format(command))
            pytest.xfail("Failed to run {} ".format(command))


@pytest.mark.parametrize('no', ('hex', 'dec'))
def test_pki_cert_hold_using_agent_cert_with_valid_nos(ansible_module, no):
    """
    :Title: Test pki ca cert with valid Agent Certificate with valid hex and decimal no.
    :Description:
        Test pki ca-cert-hold with valid Agent Certificate with valid hex and decimal no should
        able to hold the certificate.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Add the user.
        2. Issue the certificate request.
        3. Approve the certificate request.
        4. Run pki ca-cert-hold <hex_or_dec_serial>
    :Expectedresults:
        1. User should get added.
        2. Certificate should be issued.
        3. Certificate request should get approved and get the cert id.
        4. Certificate should put on the hold
    """
    userid = 'testuser{}'.format(random.randint(1111, 9999999))
    subject = 'UID={},E={}@example.org,CN={},OU=Engineering,O=Example.Org'.format(userid, userid,
                                                                                  userid)
    cert_id = user_op.process_certificate_request(ansible_module, subject=subject)
    if no == 'dec':
        cert_id = int(cert_id, 16)
    command = 'pki -d {} -c {} -p {} -n "{}" ' \
              '{} {}'.format(constants.NSSDB, constants.CLIENT_DATABASE_PASSWORD,
                             constants.CA_HTTP_PORT, 'CA_AgentV', cmd, cert_id)
    hold_out = ansible_module.expect(command=command,
                                     responses={"Are you sure \(Y\/N\)?": "Y"})
    for host, result in hold_out.items():
        if result['rc'] == 0:
            assert 'Placed certificate "{}" on-hold'.format(
                cert_id if no != 'dec' else hex(cert_id)) in result['stdout']
            assert 'Serial Number: {}'.format(cert_id if no != 'dec' else hex(cert_id)) in result[
                'stdout']
            assert 'Subject DN: {}'.format(subject) in result['stdout']
            assert 'Issuer DN: ' in result['stdout']
            assert 'Status: REVOKED' in result['stdout']
            assert 'Not Valid Before:' in result['stdout']
            assert 'Not Valid After:' in result['stdout']
            assert 'Revoked On:' in result['stdout']
            assert 'Revoked By: CA_AgentV' in result['stdout']
            log.info("Successfully run {}".format(command))
        else:
            log.error("Failed to run {}".format(command))
            log.info(result['stderr'])
            pytest.xfail("Failed to run {} ".format(command))


@pytest.mark.parametrize('no', ('0x2f3292r2', 9876598769))
def test_pki_cert_hold_using_agent_cert_with_invalid_nos(ansible_module, no):
    """
    :Title: Test pki ca-cert-hold with valid Agent Certificate with invalid serial no.
    :Description:
        Test pki ca-cert-hold with the valid Agent Certificate with invalid serial no should
        able to throw the error.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Add the user.
        2. Issue the certificate request.
        3. Approve the certificate request.
        4. Run pki ca-cert-hold <invalid_hex_or_invalid_dec_serial>
    :Expectedresults:
        1. User should get added.
        2. Certificate should be issued.
        3. Certificate request should get approved and get the cert id.
        4. Certificate should not put on the hold it should throw the error message.
    """
    error = ''
    if no == '0x2f3292r2':
        error = 'NumberFormatException: For input string: "f3292r2"'
    else:
        error = 'CertNotFoundException: Certificate ID {} not found'.format(hex(no))

    hold_out = ansible_module.pki(cli=cmd,
                                  port=constants.CA_HTTP_PORT,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  certnick="'{}'".format('CA_AgentV'),
                                  extra_args='{}'.format(no))

    for result in hold_out.values():
        log.info("Running : {}".format(result['cmd']))
        if result['rc'] == 0:
            log.error("Failed to run pki {} {}".format(cmd, no))
            pytest.xfail("Failed to run pki {} {} ".format(cmd, no))
        else:
            assert error in result['stderr']
            log.info("Successfully run pki {} ".format(result['cmd']))


def test_pki_cert_hold_using_valid_agent_cert_with_force(ansible_module):
    """
    :Title: Test pki ca-cert-hold with valid agent certificate with --force option.
    :Description:
        Test pki ca-cert-hold with valid agent ceritificate with --force option should not ask
        for choices like (Y/N)
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Add the user.
        2. Issue the certificate request.
        3. Approve the certificate request.
        4. Run pki ca-cert-hold <hex_or_dec_serial> --force
    :Expectedresults:
        1. User should get added.
        2. Certificate should be issued.
        3. Certificate request should get approved and get the cert id.
        4. Certificate should put on the hold without any confirmation message.
    """
    userid = 'testuser{}'.format(random.randint(1111, 9999999))
    subject = 'UID={},E={}@example.org,CN={},OU=Engineering,O=Example.Org'.format(userid, userid,
                                                                                  userid)
    cert_id = user_op.process_certificate_request(ansible_module, subject=subject)
    log.info("Generated certificate with Cert ID: {}".format(cert_id))
    hold_out = ansible_module.pki(cli=cmd,
                                  port=constants.CA_HTTP_PORT,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  certnick="'{}'".format('CA_AgentV'),
                                  extra_args='{} {}'.format(cert_id, '--force'))
    for result in hold_out.values():
        log.info("Running : {}".format(result['cmd']))
        if result['rc'] == 0:
            assert 'Placed certificate "{}" on-hold'.format(cert_id) in result['stdout']
            assert 'Serial Number: {}'.format(cert_id) in result['stdout']
            assert 'Subject DN: {}'.format(subject) in result['stdout']
            assert 'Issuer DN: ' in result['stdout']
            assert 'Status: REVOKED' in result['stdout']
            assert 'Not Valid Before:' in result['stdout']
            assert 'Not Valid After:' in result['stdout']
            assert 'Revoked On:' in result['stdout']
            assert 'Revoked By: CA_AgentV' in result['stdout']
            log.info("Successfully placed certificate on-hold with --force option.")
        else:
            log.error("Failed placed certificate on-hold with --force option.")
            log.info(result['stderr'])
            pytest.xfail("Failed to run pki {} {} ".format(cmd, cert_id, '--force'))


def test_pki_cert_hold_using_agent_cert_with_force_and_comment(ansible_module):
    """
    :Title: Test pki ca-cert-hold with valid Agent Cert with --force and --comment.
    :Description:
        Test pki ca-cert-hold with valid Agent Cert with --force and --comment option, it should
        able to revoke the certificate with the comment message.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Add the user.
        2. Issue the certificate request.
        3. Approve the certificate request.
        4. Run pki ca-cert-hold <hex_or_dec_serial> --force --comment "Testing"
    :Expectedresults:
        1. User should get added.
        2. Certificate should be issued.
        3. Certificate request should get approved and get the cert id.
        4. Certificate should put on the hold without any warning message and with comment.
    """
    userid = 'testuser{}'.format(random.randint(1111, 9999999))
    subject = 'UID={},E={}@example.org,CN={},OU=Engineering,O=Example.Org'.format(userid, userid,
                                                                                  userid)
    cert_id = user_op.process_certificate_request(ansible_module, subject=subject)
    log.info("Successfully generated certificate with Cert ID: {}".format(cert_id))
    hold_out = ansible_module.pki(cli=cmd,
                                  port=constants.CA_HTTP_PORT,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  certnick="'{}'".format('CA_AgentV'),
                                  extra_args='{} {}'.format(cert_id,
                                                            '--force --comments "Test Comment"'))
    for result in hold_out.values():
        log.info("Running : {}".format(result['cmd']))
        if result['rc'] == 0:
            assert 'Placed certificate "{}" on-hold'.format(cert_id) in result['stdout']
            assert 'Serial Number: {}'.format(cert_id) in result['stdout']
            assert 'Subject DN: {}'.format(subject) in result['stdout']
            assert 'Issuer DN: ' in result['stdout']
            assert 'Status: REVOKED' in result['stdout']
            assert 'Not Valid Before:' in result['stdout']
            assert 'Not Valid After:' in result['stdout']
            assert 'Revoked On:' in result['stdout']
            assert 'Revoked By: CA_AgentV' in result['stdout']
            log.info("Successfully placed certificate on-hold with --force and --comments")
        else:
            log.error("Failed to put certificate on hold with --force and --comments")
            log.info(result['stderr'])
            pytest.xfail("Failed to run pki {} {} ".format(cmd, cert_id, '--force'))


def test_pki_cert_hold_using_angent_cert_with_force_and_comment_and_dec_no(ansible_module):
    """
    :Title: Hold certificate with --force and --comment with deciman serial
    :Description:
        Test pki ca-cert-hold with valid Agent Certificate and with --force and --comment message
        should be provided with the decimal serial no. It should able to hold the certificate.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Add the user.
        2. Issue the certificate request.
        3. Approve the certificate request.
        4. Run pki ca-cert-hold <dec_serial> --force --comment "Testing"
    :Expectedresults:
        1. User should get added.
        2. Certificate should be issued.
        3. Certificate request should get approved and get the cert id.
        4. Certificate should put on the hold without any warning message and with comment.
    """
    userid = 'testuser{}'.format(random.randint(1111, 9999999))
    subject = 'UID={},E={}@example.org,CN={},OU=Engineering,O=Example.Org'.format(userid, userid,
                                                                                  userid)
    cert_id = user_op.process_certificate_request(ansible_module, subject=subject)
    log.info("Generated certificate with Cert ID: {}".format(cert_id))
    cert_id = int(cert_id, 16)
    log.info("Decimal cert ID: {}".format(cert_id))
    hold_out = ansible_module.pki(cli=cmd,
                                  port=constants.CA_HTTP_PORT,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  certnick="'{}'".format('CA_AgentV'),
                                  extra_args='{} {}'.format(cert_id,
                                                            '--force --comments "Test Comment"'))
    for result in hold_out.values():
        log.info("Running : {}".format(result['cmd']))
        if result['rc'] == 0:
            assert 'Placed certificate "{}" on-hold'.format(hex(cert_id)) in result['stdout']
            assert 'Serial Number: {}'.format(hex(cert_id)) in result['stdout']
            assert 'Subject DN: {}'.format(subject) in result['stdout']
            assert 'Issuer DN: ' in result['stdout']
            assert 'Status: REVOKED' in result['stdout']
            assert 'Not Valid Before:' in result['stdout']
            assert 'Not Valid After:' in result['stdout']
            assert 'Revoked On:' in result['stdout']
            assert 'Revoked By: CA_AgentV' in result['stdout']
            log.info("Successfully placed cert on-hold with decimal serial")
        else:
            log.error("Failed to run {} with --force and --comments")
            log.info(result['stderr'])
            pytest.xfail("Failed to run pki {} {} ".format(cmd, cert_id, '--force'))


@pytest.mark.parametrize('no', (808364891351173399048839L, 1155025308640651489455451L))
@pytest.mark.parametrize('extra_args', ('--force', '--force --comments "Test Comment"'))
def test_pki_cert_hold_using_agent_cert_with_junk_text(ansible_module, no, extra_args):
    """
    :Title: Test pki ca-cert-hold with valid Agent Certificate when serial is junk no.
    :Description:
        Test pki ca-cert-hold with valid Agent Certificate when serial is junk no. It should
        throw an error.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Add the user.
        2. Issue the certificate request.
        3. Approve the certificate request.
        4. Run pki ca-cert-hold <junk_serial> --force --comment "Testing"
    :Expectedresults:
        1. User should get added.
        2. Certificate should be issued.
        3. Certificate request should get approved and get the cert id.
        4. Certificate should not put on hold instead it should throw an error message.
    """
    hex_no = no
    if hex(no).endswith("L"):
        hex_no = str(hex(no))[:-1]
    hold_out = ansible_module.pki(cli=cmd,
                                  port=constants.CA_HTTP_PORT,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  certnick="'{}'".format('CA_AgentV'),
                                  extra_args='{} {}'.format(hex_no, extra_args))

    for result in hold_out.values():
        log.info("Running : {}".format(result['cmd']))
        if result['rc'] == 0:
            log.error("Failed to run pki {} {} {}".format(cmd, hex_no, extra_args))
            log.info(result['stderr'])
            pytest.xfail("Failed to run pki {} {} ".format(cmd, hex_no))
        else:
            assert 'CertNotFoundException: Certificate ID {} ' \
                   'not found'.format(hex_no) in result['stderr']
            log.info("Successfully run pki {} {} {}".format(cmd, hex_no, extra_args))


@pytest.mark.parametrize('nick', ('CA_AdminV', 'CA_AdminR', 'CA_AdminE'))
def test_pki_cert_hold_using_agent_cert_with_different_admin_cert(ansible_module, nick):
    """
    :Title: Test pki ca-cert-hold with different Admin Certificate.
    :Description: Pki ca-cert-hold with different Admin Certificate should able to throw the
        should throw an error message.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Add the user.
        2. Issue the certificate request.
        3. Approve the certificate request.
        4. Run pki -n CA_AdminE ca-cert-hold <valid_serial> --force --comment "Testing"
           pki -n CA_AdminR ca-cert-hold <valid_serial> --force --comment "Testing"
    :Expectedresults:
        1. User should get added.
        2. Certificate should be issued.
        3. Certificate request should get approved and get the cert id.
        4. Certificate should not put on hold instead it should throw an error message.
    """
    error = ''
    if nick.endswith('V'):
        error = 'Authorization Error'
    elif nick.endswith('R'):
        error = 'PKIException: Unauthorized'
    elif nick.endswith('E'):
        error = 'FATAL: SSL alert received: CERTIFICATE_EXPIRED\n' \
                'IOException: SocketException cannot write on socket'
    userid = 'testuser{}'.format(random.randint(1111, 9999999))
    subject = 'UID={},E={}@example.org,CN={},OU=Engineering,O=Example.Org'.format(userid, userid,
                                                                                  userid)
    cert_id = user_op.process_certificate_request(ansible_module, subject=subject)
    log.info("Successfully generated certificate with Cert ID: {}".format(cert_id))
    hold_out = ansible_module.pki(cli=cmd,
                                  port=constants.CA_HTTP_PORT,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  certnick="'{}'".format(nick),
                                  extra_args='{}'.format(cert_id))

    for result in hold_out.values():
        log.info("Running : {}".format(result['cmd']))
        if result['rc'] == 0:
            log.error("Failed to run pki -n '{}' {} {}".format(nick, cmd, cert_id))
            log.info(result['stderr'])
            pytest.xfail("Failed to run pki {} {} ".format(cmd, cert_id))
        else:
            assert error in result['stderr']
            log.info("Successfully run pki -n '{}' {} {}".format(nick, cmd, cert_id))


@pytest.mark.parametrize('nick', ('CA_AgentR', 'CA_AgentE',))
def test_pki_cert_hold_using_agent_cert_with_different_agent_cert(ansible_module, nick):
    """
    :Title: Test pki ca-cert-hold with different Agent Certificate.
    :Description: Pki ca-cert-hold with different Agent Certificate should able to throw the
        should throw an error message.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Add the user.
        2. Issue the certificate request.
        3. Approve the certificate request.
        4. Run pki -n CA_AgentE ca-cert-hold <valid_serial> --force --comment "Testing"
           pki -n CA_AgentR ca-cert-hold <valid_serial> --force --comment "Testing"
    :Expectedresults:
        1. User should get added.
        2. Certificate should be issued.
        3. Certificate request should get approved and get the cert id.
        4. Certificate should not put on hold instead it should throw an error message.
    """
    error = ''

    if nick.endswith('R'):
        error = 'PKIException: Unauthorized'
    elif nick.endswith('E'):
        error = 'FATAL: SSL alert received: CERTIFICATE_EXPIRED\n' \
                'IOException: SocketException cannot write on socket'

    userid = 'testuser{}'.format(random.randint(1111, 9999999))
    subject = 'UID={},E={}@example.org,CN={},OU=Engineering,O=Example.Org'.format(userid, userid,
                                                                                  userid)
    cert_id = user_op.process_certificate_request(ansible_module, subject=subject)
    log.info("Successfully generated cert with Cert ID: {}".format(cert_id))
    hold_out = ansible_module.pki(cli=cmd,
                                  port=constants.CA_HTTP_PORT,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  certnick="'{}'".format(nick),
                                  extra_args='{}'.format(cert_id))

    for result in hold_out.values():
        log.info("Running : {}".format(result['cmd']))
        if result['rc'] == 0:
            log.error("Failed to run pki {} {}".format(cmd, cert_id))
            log.info(result['stderr'])
            pytest.xfail("Failed to run pki {} {} ".format(cmd, cert_id))
        else:
            assert error in result['stderr']
            log.info("Successfully run pki {} {}".format(cmd, cert_id))


def test_pki_cert_hold_using_agent_cert_with_audit_cert(ansible_module):
    """
    :Title: Test pki ca-cert-hold with different Audit Certificate.
    :Description: Pki ca-cert-hold with different Audit Certificate should able to throw the
        should throw an error message.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Add the user.
        2. Issue the certificate request.
        3. Approve the certificate request.
        4. Run pki -n CA_AuditV ca-cert-hold <valid_serial> --force --comment "Testing"
           pki -n CA_AuditR ca-cert-hold <valid_serial> --force --comment "Testing"
    :Expectedresults:
        1. User should get added.
        2. Certificate should be issued.
        3. Certificate request should get approved and get the cert id.
        4. Certificate should not put on hold instead it should throw an error message.
    """
    userid = 'testuser{}'.format(random.randint(1111, 9999999))
    subject = 'UID={},E={}@example.org,CN={},OU=Engineering,O=Example.Org'.format(userid, userid,
                                                                                  userid)
    cert_id = user_op.process_certificate_request(ansible_module, subject=subject)
    log.info("Successfully generated cert with Cert ID: {}".format(cert_id))
    hold_out = ansible_module.pki(cli=cmd,
                                  port=constants.CA_HTTP_PORT,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  certnick="'{}'".format('CA_AuditV'),
                                  extra_args='{}'.format(cert_id))

    for result in hold_out.values():
        log.info("Running : {}".format(result['cmd']))
        if result['rc'] == 0:
            log.error("Failed to run pki {} {}".format(cmd, cert_id))
            log.info(result['stderr'])
            pytest.xfail("Failed to run pki {} {} ".format(cmd, cert_id))
        else:
            assert 'Authorization Error' in result['stderr']
            log.info("Successfully run pki -n '{}' {} {}".format('CA_AuditV', cmd, cert_id))


def test_pki_cert_hold_when_cert_already_revoked(ansible_module):
    """
    :Title: Test put the certificate on hold when it is already revoked.
    :Description:
        Test pki ca-cert-hold with valid Agent Certificate should not able to put the certificate
        on hold if certificate is already revoked.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Add the user.
        2. Issue the certificate request.
        3. Approve the certificate request.
        4. Revoke the certificate.
        4. Run pki -n CA_AuditV ca-cert-hold <valid_serial> --force --comment "Testing"
    :Expectedresults:
        1. User should get added.
        2. Certificate should be issued.
        3. Certificate request should get approved and get the cert id.
        4. Revoked Certificate should not put on hold instead it should show an error
            message that it is already Revoked.
    """
    userid = 'testuser{}'.format(random.randint(1111, 9999999))
    subject = 'UID={},E={}@example.org,CN={},OU=Engineering,O=Example.Org'.format(userid, userid,
                                                                                  userid)
    # Generate the certificate and revoke it.
    cert_id = user_op.process_certificate_request(ansible_module, subject=subject, action='approve',
                                                  revoke=True)
    log.info("Generated certificate with Cert ID: {}".format(cert_id))

    hold_out = ansible_module.pki(cli=cmd,
                                  port=constants.CA_HTTP_PORT,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  certnick="'{}'".format('CA_AgentV'),
                                  extra_args='{} --force'.format(cert_id))

    for result in hold_out.values():
        log.info("Running : {}".format(result['cmd']))
        if result['rc'] == 0:
            log.error("Failed to run pki {} {}".format(cmd, cert_id))
            log.info(result['stderr'])
            pytest.xfail("Failed to run pki {} {} ".format(cmd, cert_id))
        else:
            assert 'BadRequestException: certificate #{} has ' \
                   'already been revoked'.format(cert_id.split('x')[1]) in result['stderr']
            log.info("Successfully run pki -n '{}' {} {}".format('CA_AuditV', cmd, cert_id))


def test_pki_cert_hold_using_normal_user_without_any_privileges(ansible_module):
    """
    :Title: Test pki ca-cert-hold with normal user who do not have any privileges.
    :Description:
        Test pki ca-cert-hold with normal user who do not have any privileges should not able
        to put certificate on hold.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Add the user.
        2. Issue the certificate request.
        3. Approve the certificate request.
        4. Run pki -n testuser9 ca-cert-hold <valid_serial> --force --comment "Testing"
    :Expectedresults:
        1. User should get added.
        2. Certificate should be issued.
        3. Certificate request should get approved and get the cert id.
        4. User who do not have any privileges not able to put the certificate on hold.
    """
    userid = 'testuser{}'.format(random.randint(1111, 9999999))
    subject = 'UID={},E={}@example.org,CN={},OU=Engineering,O=Example.Org'.format(userid, userid,
                                                                                  userid)
    cert_id = user_op.process_certificate_request(ansible_module, subject=subject)
    log.info("Generated certificate with Cert ID: {}".format(cert_id))
    import_cert = ansible_module.pki(cli='client-cert-import',
                                     port=constants.CA_HTTP_PORT,
                                     nssdb=constants.NSSDB,
                                     certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                     extra_args='{} --serial {}'.format(userid, cert_id))
    for result in import_cert.values():
        log.info("Running : {}".format(result['cmd']))
        if result['rc'] == 0:
            assert 'Imported certificate "{}"'.format(userid) in result['stdout']
            log.info("Certificate imported to client-database")
        else:
            log.error("Failed to import certificate to client-database.")
            pytest.xfail()

    userid1 = 'testuser10'
    subject1 = 'UID={},E={}@example.org,CN={},OU=Engineering,O=Example.Org'.format(userid1, userid1,
                                                                                   userid1)
    cert_id1 = user_op.process_certificate_request(ansible_module, subject=subject1)
    log.info("Generate New certificate with Cert ID: {}".format(cert_id1))
    hold_out = ansible_module.pki(cli=cmd,
                                  port=constants.CA_HTTP_PORT,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  certnick="'{}'".format(userid),
                                  extra_args='{} --force'.format(cert_id1))

    for result in hold_out.values():
        log.info("Running : {}".format(result['cmd']))
        if result['rc'] == 0:
            log.error("Failed to run pki {} {}".format(cmd, cert_id))
            log.info(result['stderr'])
            pytest.xfail("Failed to run pki {} {} ".format(cmd, cert_id))
        else:
            assert 'PKIException: Unauthorized'.format(cert_id) in result['stderr']
            log.info("Successfully run pki -n '{}' {} {}".format(userid, cmd, cert_id1))
    ansible_module.command('pki -d {} -c {} client-cert-del '
                           '{}'.format(constants.NSSDB, constants.CLIENT_DATABASE_PASSWORD, userid))
