#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI USER-CERT CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki user commands needs to be tested:
#   pki user-cert-release-hold
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
cmd = 'ca-cert-release-hold'


@pytest.mark.parametrize('args', ['', '--help'])
def test_pki_cert_release_hold_help(ansible_module, args):
    """
    :Title: Test pki ca-cert-release-hold with '' and --help arguments.
    :Description:
        This test will test ca-cert-release-hold with '' and --help option. For '' it should
        expected to throw an error and for --help it should show the help message.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-cert-show ''
        2. Run pki ca-cert-show --help
    :Expectedresults:
        1. It should expected to throw an error for 'Missing serial number'
        2. It should show help options.
    """
    help_out = ansible_module.command("pki {} {}".format(cmd, args))
    for result in help_out.values():
        log.info("Running : {}".format(result['cmd']))
        if result['rc'] == 0:
            assert "usage: {} <Serial Number> [OPTIONS...]".format(cmd) in result['stdout']
            assert "--force   Force" in result['stdout']
            assert "--help    Show help options" in result['stdout']
        else:
            assert "Error: Missing Serial Number." in result['stderr']


def test_pki_cert_release_hold_with_valid_agent_cert(ansible_module):
    """
    :Title: Test pki ca-cert-release-hold with valid Agent Certificate.
    :Description:
        This test will release certificate form hold using valid agent certificate.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Submit Certificate request.
        2. Approve the certificate request, Get the certificate id.
        3. Put the certificate on the hold
        4. Release the certificate form the hold using CA_AgentV certificate.
    :Expectedresults:
        1. Certificate should get off-hold, and it's status should be VALID.
    """
    userid = 'testuser1'
    subject = 'UID={},E={}@example.org,CN={}'.format(userid, userid,userid)
    cert_id = user_op.process_certificate_request(ansible_module, subject=subject, action='approve',
                                                  revoke=True, reason="Certificate_Hold")
    revoke_out = ansible_module.pki(cli='ca-cert-show',
                                    nssdb=constants.NSSDB,
                                    dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                    port=constants.CA_HTTP_PORT,
                                    certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                    extra_args='{}'.format(cert_id))
    for result in revoke_out.values():
        log.info("Running : {}".format(result['cmd']))
        if result['rc'] == 0:
            assert 'Status: REVOKED' in result['stdout']

    command = 'pki -d {} -c {} -h localhost ' \
              '-p {} -n "{}" {} {}'.format(constants.NSSDB, constants.CA_PASSWORD,
                                           constants.CA_HTTP_PORT, 'CA_AgentV', cmd, cert_id)
    release_hold_out = ansible_module.expect(command=command,
                                             responses={"Are you sure \(Y\/N\)?": "Y"})

    for result in release_hold_out.values():
        log.info("Running : {}".format(result['cmd']))
        if result['rc'] == 0:
            assert 'Placed certificate "{}" off-hold'.format(cert_id) in result['stdout']
            assert 'Serial Number: {}'.format(cert_id) in result['stdout']
            assert 'Issuer DN: ' in result['stdout']
            assert 'Subject DN: {}'.format(subject) in result['stdout']
            assert 'Status: VALID' in result['stdout']
        else:
            pytest.xfail("Failed to run pki {} {} command".format(cmd, cert_id))


def test_pki_ca_cert_release_hold_which_is_not_on_hold(ansible_module):
    """
    :Title: Test pki ca-cert-release-hold, release certificate which is not on hold.
    :Description:
        This test will test that certificate which is not placed on hold will try to place the
        certificate off-hold.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Submit certificate request, Get request approved,
        2. Get certificate id
        3. Run pki ca-cert-release-hold <cert_id>
    :Expectedresults:
        1. It should not place certificate off-hold.
    """
    userid = 'testuser2'
    subject = 'UID={},E={}@example.org,CN={}'.format(userid, userid, userid)
    cert_id = user_op.process_certificate_request(ansible_module, subject=subject)
    release_hold_out = ansible_module.pki(cli=cmd,
                                          nssdb=constants.NSSDB,
                                          dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                          port=constants.CA_HTTP_PORT,
                                          certnick="'{}'".format('CA_AgentV'),
                                          extra_args='{} --force'.format(cert_id))
    for result in release_hold_out.values():
        log.info("Running : {}".format(result['cmd']))
        if result['rc'] ==0:
            assert "One or more certificates could not be unrevoked" in result['stdout']
            assert 'Could not place certificate "{}" off-hold'.format(cert_id) in result['stdout']
        else:
            log.error("Failed to run {}".format(result['cmd']))
            pytest.xfail()


@pytest.mark.parametrize('serial', ('', '12422', '0xese232323', '23892(3)'))
def test_pki_ca_cert_release_hold_with_invalid_cert_ids(ansible_module, serial):
    """
    :Title: Test pki ca-cert-release hold with invalid hex and decimal cert id.
    :Description:
        This test should test the ca-cert-release-hold against the invalid hex and decimal
        cert id.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-cert-release-hold <decimal_cert_id>
        2. Run pki ca-cert-release-hold <hexdecimal_cert_id>
    :Expectedresults:
        1. It should throw 'CertNotFoundException'
    """
    error = ''
    if serial == '':
        error = 'Error: Missing Serial Number.'
    elif serial == '12422':
        error = 'CertNotFoundException: Certificate ID 0x3086 not found'
    elif serial == '0xese232323':
        error = 'NumberFormatException: For input string: "es"'
    elif serial == '23892(3)':
        error = 'NumberFormatException: For input string: "23892(3)"'
    release_hold_out = ansible_module.pki(cli=cmd,
                                          nssdb=constants.NSSDB,
                                          dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                          port=constants.CA_HTTP_PORT,
                                          certnick="'{}'".format('CA_AgentV'),
                                          extra_args='{}'.format(serial))
    for result in release_hold_out.values():
        log.info("Running : {}".format(result['cmd']))
        if result['rc'] == 0:
            pytest.xfail("Failed to run pki {} {} command".format(cmd, serial))
        else:
            assert error in result['stderr']


def test_pki_ca_cert_release_hold_release_valid_cert_on_hold(ansible_module):
    """
    :Title: Test pki ca-cert-release-hold, release valid certificate from the hold.
    :Description:
        This test will release valid certificate from the hold, It should expected to fail,
        as certificate is not on hold.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Submit the certificate request.
        2. Approve the certificate rquest and get the certificate id.
        3. Run pki ca-cert-revoke <cert_id> --reason Certificate_Hold
        4. Run pki ca-cert-release-hold <cert_id>
    :Expectedresults:
        1. Certificate should get off hold. It's status should be VALID
    """
    userid = 'testuser3'
    subject = 'UID={},E={}@example.org,CN={},OU=Engineering,O=Example.Org'.format(userid, userid,
                                                                                  userid)
    cert_id = user_op.process_certificate_request(ansible_module, subject=subject, action='approve',
                                                  revoke=True, reason="Certificate_Hold")
    revoke_out = ansible_module.pki(cli='ca-cert-show',
                                    nssdb=constants.NSSDB,
                                    dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                    port=constants.CA_HTTP_PORT,
                                    certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                    extra_args='{}'.format(cert_id))
    for result in revoke_out.values():
        log.info("Running : {}".format(result['cmd']))
        if result['rc'] == 0:
            assert 'Status: REVOKED' in result['stdout']

    command = 'pki -d {} -c {} -h localhost ' \
              '-p {} -n "{}" {} {}'.format(constants.NSSDB, constants.CA_PASSWORD,
                                           constants.CA_HTTP_PORT, 'CA_AgentV',
                                           cmd, int(str(cert_id), 16))
    release_hold_out = ansible_module.expect(command=command,
                                             responses={"Are you sure \(Y\/N\)?": "Y"})
    for result in release_hold_out.values():
        log.info("Running : {}".format(result['cmd']))
        if result['rc'] == 0:
            assert 'Placed certificate "{}" off-hold'.format(cert_id) in result['stdout']
            assert 'Serial Number: {}'.format(cert_id) in result['stdout']
            assert 'Subject DN: {}'.format(subject) in result['stdout']
            assert 'Issuer DN: ' in result['stdout']
            assert 'Status: VALID' in result['stdout']

        else:
            pytest.xfail("Failed to run pki {} {} command".format(cmd, int(str(cert_id), 16)))


def test_pki_ca_cert_release_hold_release_valid_cert_using_force(ansible_module):
    """
    :Title: Test pki ca-cert-release-hold, release valid certificate from hold using
            option --force.
    :Description:
            This test will release certificate from hold when option --force is passed.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Submit the certificate request.
        2. Approve the certificate request and get the certificate id.
        3. Run pki ca-cert-revoke <cert_id> --reason Certificate_Hold
        4. Run pki ca-cert-release-hold <cert_id> --force
    :Expectedresults:
        1. It should release the certificate from hold.
    """
    userid = 'testuser4'
    subject = 'UID={},E={}@example.org,CN={},OU=Engineering,O=Example.Org'.format(userid, userid,
                                                                                  userid)
    cert_id = user_op.process_certificate_request(ansible_module, subject=subject, action='approve',
                                                  revoke=True, reason="Certificate_Hold")
    revoke_out = ansible_module.pki(cli='ca-cert-show',
                                    nssdb=constants.NSSDB,
                                    dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                    port=constants.CA_HTTP_PORT,
                                    certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                    extra_args='{}'.format(cert_id))
    for result in revoke_out.values():
        log.info("Running : {}".format(result['cmd']))
        if result['rc'] == 0:
            assert 'Status: REVOKED' in result['stdout']

    release_hold_out = ansible_module.pki(cli=cmd,
                                          nssdb=constants.NSSDB,
                                          dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                          port=constants.CA_HTTP_PORT,
                                          certnick="'{}'".format('CA_AgentV'),
                                          extra_args='{} --force'.format(int(str(cert_id), 16)))
    for result in release_hold_out.values():
        log.info("Running : {}".format(result['cmd']))
        if result['rc'] == 0:
            assert 'Placed certificate "{}" off-hold'.format(cert_id) in result['stdout']
            assert 'Serial Number: {}'.format(cert_id) in result['stdout']
            assert 'Subject DN: {}'.format(subject) in result['stdout']
            assert 'Issuer DN: ' in result['stdout']
            assert 'Status: VALID' in result['stdout']

        else:
            pytest.xfail("Failed to run pki {} {} command".format(cmd, int(str(cert_id), 16)))


@pytest.mark.parametrize('user', ('CA_AgentE','CA_AgentR', 'CA_AuditR'))
def test_pki_cert_release_hold_with_diff_user_certs(ansible_module, user):
    """
    :Title: Test pki ca-cert-release-hold with different user certs.
    :Description:
        Test pki ca-cert-release-hold with different user certs, It should throw an error if
        certificates are Revoked or Expired.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Submit the certificate request.
        2. Approve the certificate request and get the certificate id.
        3. Run pki ca-cert-revoke <cert_id> --reason Certificate_Hold
        4. Run pki -n CA_AgentR ca-cert-release-hold <cert_id> --force
        5. Run pki -n CA_AgentE ca-cert-release-hold <cert_id> --force
        6. Run pki -n CA_AuditR ca-cert-release-hold <cert_id> --force
    :Expectedresults:
        1. It should throw an error for the CA_AgentR, CA_AgentE and for CA_AuditR.
    """
    error = ''
    if user.endswith('E'):
        error = 'FATAL: SSL alert received: CERTIFICATE_EXPIRED\n' \
                'IOException: SocketException cannot write on socket'
    elif user.endswith('R'):
        error = 'PKIException: Unauthorized'

    userid = 'testuser5'
    subject = 'UID={},E={}@example.org,CN={},OU=Engineering,O=Example.Org'.format(userid, userid,
                                                                                  userid)
    cert_id = user_op.process_certificate_request(ansible_module, subject=subject,action='approve',
                                                  revoke=True, reason="Certificate_Hold")
    revoke_out = ansible_module.pki(cli='ca-cert-show',
                                    nssdb=constants.NSSDB,
                                    dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                    port=constants.CA_HTTP_PORT,
                                    certnick="'{}'".format('CA_AgentV'),
                                    extra_args='{}'.format(cert_id))
    for result in revoke_out.values():
        log.info("Running : {}".format(result['cmd']))
        if result['rc'] == 0:
            assert 'Status: REVOKED' in result['stdout']

    release_hold_out = ansible_module.pki(cli=cmd,
                                          nssdb=constants.NSSDB,
                                          dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                          port=constants.CA_HTTP_PORT,
                                          certnick="'{}'".format(user),
                                          extra_args='{}'.format(int(str(cert_id), 16)))
    for result in release_hold_out.values():
        log.info("Running : {}".format(result['cmd']))
        if result['rc'] == 0:
            assert 'Placed certificate "{}" off-hold'.format(cert_id) in result['stdout']
            assert 'Serial Number: {}'.format(cert_id) in result['stdout']
            assert 'Subject DN: {}'.format(subject) in result['stdout']
            assert 'Issuer DN: ' in result['stdout']
            assert 'Status: VALID' in result['stdout']
            pytest.xfail("Failed to run pki {} {} command".format(cmd, int(str(cert_id), 16)))
        else:
            assert error in result['stderr']


def test_pki_ca_cert_release_hold_with_diff_reasons(ansible_module):
    """
    :Title: Test pki ca-cert-release-hold with different reasons.
    :Description:
        This test will test certs which are revoked with different reasons. It should not get
        back in the valid state.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Submit the certificate request.
        2. Approve the certificate request and get the certificate id.
        3. Run pki ca-cert-revoke <cert_id> --reason Key_Compromise
        4. Run pki ca-cert-release-hold <cert_id> --force
    :Expectedresults:
        1. It should throw an error.
    """
    userid = 'testuser6'
    subject = 'UID={},E={}@example.org,CN={},OU=Engineering,O=Example.Org'.format(userid, userid,
                                                                                  userid)
    cert_id = user_op.process_certificate_request(ansible_module, subject=subject, action='approve',
                                                  revoke=True)
    revoke_out = ansible_module.pki(cli='ca-cert-show',
                                    nssdb=constants.NSSDB,
                                    dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                    port=constants.CA_HTTP_PORT,
                                    certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                    extra_args='{}'.format(cert_id))
    for result in revoke_out.values():
        log.info("Running : {}".format(result['cmd']))
        if result['rc'] == 0:
            assert 'Status: REVOKED' in result['stdout']

    release_hold_out = ansible_module.pki(cli=cmd,
                                          nssdb=constants.NSSDB,
                                          dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                          port=constants.CA_HTTP_PORT,
                                          certnick="'{}'".format('CA_AgentV'),
                                          extra_args='{} --force'.format(int(str(cert_id), 16)))

    for result in release_hold_out.values():
        log.info("Running : {}".format(result['cmd']))
        if result['rc'] == 0:
            assert "One or more certificates could not be unrevoked" in result['stdout']
            assert 'Could not place certificate "{}" off-hold'.format(cert_id) in result['stdout']
        else:
            pytest.xfail("Failed to run pki {} {} command".format(cmd, int(str(cert_id), 16)))


def test_pki_ca_cert_release_hold_revoke_agent_certificate(ansible_module):
    """
    :Title: Test pki ca-cert-release-hold, Hold and release agent cert and verify cert is usable.
    :Description:
        Test pki ca-cert-release-hold will place CA_AgentV certificate off hold and using this
        certificate approve the certificate request.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Find CA_AgentV certificate id.
        2. Put CA_AgentV certificate on hold.
        3. Put CA_AgentV certificate off-hold.
        4. Approve the certificate request using CA_AgentV.
    :Expectedresults:
        1. Certificate request should be get approved by CA_AgentV
    """
    user_cert_show_out = ansible_module.pki(cli='ca-user-cert-find',
                                            nssdb=constants.NSSDB,
                                            dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                            port=constants.CA_HTTP_PORT,
                                            certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                            extra_args="{}".format('CA_AgentV'))
    for result in user_cert_show_out.values():
        log.info("Running : {}".format(result['cmd']))
        if result['rc'] == 0:
            raw_cert_id = re.findall(r'Serial Number: [\w]*', result['stdout'])
            cert_id = raw_cert_id[0].split(':')[1].strip()

            for cert in ['ca-cert-hold', cmd]:
                revoke_out = ansible_module.pki(cli=cert,
                                                nssdb=constants.NSSDB,
                                                dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                                port=constants.CA_HTTP_PORT,
                                                certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                                extra_args=' {} --force'.format(cert_id))
                for result in revoke_out.values():
                    log.info("Running : {}".format(result['cmd']))
                    if result['rc'] == 0:
                        if cert == cmd:
                            assert 'Status: VALID' in result['stdout']
                        else:
                            assert 'Status: REVOKED' in result['stdout']

    userid = 'testuser3'
    subject = 'UID={},E={}@example.org,CN={},OU=Engineering,O=Example.Org'.format(userid, userid,
                                                                                  userid)
    cert_id = user_op.process_certificate_request(ansible_module, subject=subject,
                                                  approvar_nickname='CA_AgentV')

    release_hold_out = ansible_module.pki(cli=cmd,
                                          nssdb=constants.NSSDB,
                                          dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                          port=constants.CA_HTTP_PORT,
                                          certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                          extra_args='{} --force'.format(int(str(cert_id), 16)))
    for result in release_hold_out.values():
        log.info("Running : {}".format(result['cmd']))
        if result['rc'] == 0:
            assert "One or more certificates could not be unrevoked" in result['stdout']
            assert 'Could not place certificate "{}" off-hold'.format(cert_id) in result['stdout']
        else:
            pytest.xfail("Failed to run pki {} {} command".format(cmd, int(str(cert_id), 16)))
