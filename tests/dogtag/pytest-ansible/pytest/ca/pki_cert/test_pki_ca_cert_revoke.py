#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI USER-CERT CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki user commands needs to be tested:
#   pki user-cert-revoke
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
import shutil
import sys
import tempfile
from lxml import etree

import pytest

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
cmd = 'ca-cert-revoke'


@pytest.mark.parametrize('subcmd', ('', '--help', 'asdfa'))
def test_pki_cert_revoke_help(ansible_module, subcmd):
    """
    :Title: Test pki ca-cert-revoke with '' and --help command.
    :Description:
        Test pki ca-cert-revoke with '' and --help, it should able to throw an error when
        we pass '' and able to show the help message when --help passed.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-cert-revoke ''
        2. Run pki ca-cert-revoke --help
    :Expectedresults:
        1. It should throw an error.
        2. It should show help message.
    """
    help_out = ansible_module.pki(cli=cmd,
                                  port=constants.CA_HTTP_PORT,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                  extra_args='{}'.format(subcmd))
    for host, result in help_out.items():
        if result['rc'] == 0:
            assert 'usage: {} <Serial Number> [OPTIONS...]'.format(cmd) in result['stdout']
            assert '--ca                    CA signing certificate' in result['stdout']
            assert '--comments <comments>   Comments' in result['stdout']
            assert '--force                 Force' in result['stdout']
            assert '--help                  Show help options' in result['stdout']
            assert '--reason <reason>       Revocation reason: Unspecified (default),' \
                   in result['stdout']
            assert '                            Key_Compromise, CA_Compromise,' in result['stdout']
            assert '                            Affiliation_Changed, Superseded,' \
                   in result['stdout']
            assert '                            Cessation_of_Operation, Certificate_Hold,' in \
                   result['stdout']
            assert '                            Remove_from_CRL, Privilege_Withdrawn,' in \
                   result['stdout']
            assert '                            AA_Compromise' in result['stdout']
        elif subcmd == 'asdfa':
            assert 'NumberFormatException: For input string: "asdfa"' in result['stderr']
        else:
            assert 'Error: Missing Serial Number.' in result['stderr']


def test_pki_cert_revoke_with_agent_certificate(ansible_module):
    """
    :Title: Test pki ca-cert-revoke with valid Agent Certificate and valid hex no.
    :Description: This test able to revoke the certificate with valid hex serial no
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-cert-revoke <valid_hex_serial_no>
    :Expectedresults:
        1. It should able to revoke the certificate.
    """
    userid = 'testuser1'
    subject = 'UID={},E={}@example.org,CN={}'.format(userid, userid,userid)
    cert_id = user_op.process_certificate_request(ansible_module, subject=subject)

    command = 'pki -d {} -c {} -p {} -n "{}" {} ' \
              '{}'.format(constants.NSSDB, constants.CLIENT_DATABASE_PASSWORD,
                          constants.CA_HTTP_PORT, 'CA_AgentV', cmd, cert_id)

    revoke_out = ansible_module.expect(command=command,
                                       responses={"Are you sure \(Y\/N\)?": "Y"})
    for host, result in revoke_out.items():
        if result['rc'] == 0:
            assert 'Revoked certificate "{}"'.format(cert_id) in result['stdout']
            assert 'Serial Number: {}'.format(cert_id) in result['stdout']
            assert 'Issuer DN: ' in result['stdout']
            assert 'Subject DN: {}'.format(subject) in result['stdout']
            assert 'Status: REVOKED' in result['stdout']
            assert 'Not Valid Before: ' in result['stdout']
            assert 'Not Valid After: ' in result['stdout']
            assert 'Revoked On:' in result['stdout']
            assert 'Revoked By: CA_AgentV' in result['stdout']
        else:
            pytest.xfail("Failed to run pki {} {}".format(cmd, cert_id))


def test_pki_cert_revoke_with_comments(ansible_module):
    """
    :Title: Test pki ca-cert-revoke with valid Agent Certificate and with --comments.
    :Description:
        This test will revoke the certificate when serial no is passed to
        the command with --comment.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-cert-revoke <valid_decimal_no> --comments "Test comment"
    :Expectedresults:
        1. Command able to revoke the certificate with decimal serial no with the comments.
    """
    userid = 'testuser2'
    subject = 'UID={},E={}@example.org,CN={}'.format(userid, userid,userid)
    cert_id = user_op.process_certificate_request(ansible_module, subject=subject)
    decimal = int(str(cert_id), 16)
    command = 'pki -d {} -c {} -p {} -n "{}" {} {} --comments ' \
              '"Test comment1"'.format(constants.NSSDB,constants.CLIENT_DATABASE_PASSWORD,
                                       constants.CA_HTTP_PORT, 'CA_AgentV', cmd, decimal)
    revoke_out = ansible_module.expect(command=command,
                                       responses={"Are you sure \(Y\/N\)?": "Y"})

    for result in revoke_out.values():
        if result['rc'] == 0:
            assert 'Revoked certificate "{}"'.format(cert_id) in result['stdout']
            assert 'Serial Number: {}'.format(cert_id) in result['stdout']
            assert 'Subject DN: {}'.format(subject) in result['stdout']
            assert 'Issuer DN: ' in result['stdout']
            assert 'Status: REVOKED' in result['stdout']
            assert 'Not Valid Before: ' in result['stdout']
            assert 'Not Valid After: ' in result['stdout']
            assert 'Revoked On:' in result['stdout']
            assert 'Revoked By: CA_AgentV' in result['stdout']
        else:
            pytest.xfail("Failed to run pki {} {}".format(cmd, decimal))


def test_pki_cert_revoke_with_force(ansible_module):
    """
    :Title: Test pki ca-cert-revoke with invalid no.
    :Description:
        This test will not able to revoke the certificate when invalid no is passed to the
        command, it should able to throw the error.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-cert-revoke <invalid_serial_no>
    :Expectedresults:
        1. Command should not able to revoke the certificate and it should able to
        throw an error message.
    """
    userid = 'testuser3'
    subject = 'UID={},E={}@example.org,CN={}'.format(userid, userid,userid)
    cert_id = user_op.process_certificate_request(ansible_module, subject=subject)
    revoke_out = ansible_module.pki(cli=cmd,
                                    nssdb=constants.NSSDB,
                                    dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                    port=constants.CA_HTTP_PORT,
                                    certnick="'{}'".format('CA_AgentV'),
                                    extra_args=' {} --force'.format(cert_id))

    for host, result in revoke_out.items():
        if result['rc'] == 0:
            assert 'Revoked certificate "{}"'.format(cert_id) in result['stdout']
            assert 'Serial Number: {}'.format(cert_id) in result['stdout']
            assert 'Subject DN: {}'.format(subject) in result['stdout']
            assert 'Issuer DN: ' in result['stdout']
            assert 'Status: REVOKED' in result['stdout']
            assert 'Not Valid Before: ' in result['stdout']
            assert 'Not Valid After: ' in result['stdout']
            assert 'Revoked On:' in result['stdout']
            assert 'Revoked By: CA_AgentV' in result['stdout']
        else:
            pytest.xfail("Failed to run pki {} {} --force".format(cmd, cert_id))


@pytest.mark.parametrize('reason', ('unspecified', 'Key_Compromise', 'CA_Compromise',
                                    'Affiliation_Changed', 'Superseded', 'Cessation_of_Operation',
                                    'Certificate_Hold', 'Privilege_Withdrawn', 'Remove_from_CRL',
                                    pytest.mark.xfail('"Invalid revocation reason"')))
def test_pki_cert_revoke_with_reason(ansible_module, reason):
    """
    :Title:
        Test pki ca-cert-revoke with the different reasons unspecified, Key_Compromise,
        CA_Compromise, Affiliation_Changed, Superseded, Cessation_of_Operation, Certificate_Hold,
        Privilege_Withdrawn, Remove_from_CRL and with invalid Reason.
    :Description:
        Test pki ca-cert-revoke with the different reasons unspecified, Key_Compromise,
        CA_Compromise, Affiliation_Changed, Superseded, Cessation_of_Operation, Certificate_Hold,
        Privilege_Withdrawn, Remove_from_CRL and with invalid Reason. Command should able to revoke
        the certificate with the specified reason.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-cert-revoke <serial_no> --reason unspecified
        2. Run pki ca-cert-revoke <serial_no> --reason Key_Compromise
        3. Run pki ca-cert-revoke <serial_no> --reason CA_Compromise
        4. Run pki ca-cert-revoke <serial_no> --reason Affiliation_Changed
        5. Run pki ca-cert-revoke <serial_no> --reason Cessation_of_Operation
        6. Run pki ca-cert-revoke <serial_no> --reason Certificate_Hold
        7. Run pki ca-cert-revoke <serial_no> --reason Privilege_Withdrawn
        8. Run pki ca-cert-revoke <serial_no> --reason Remove_from_CRL
        9. Run pki ca-cert-revoke <serial_no> --reason Invalid Reason.

    :Expectedresults:
        1. Certificate should revoked with the reason unspecified
        2. Certificate should revoked with the reason Key_Compromise
        3. Certificate should revoked with the reason CA_Compromise
        4. Certificate should revoked with the reason Affiliation_Changed
        5. Certificate should revoked with the reason Cessation_of_Operation
        6. Certificate should revoked with the reason Certificate_Hold
        7. Certificate should revoked with the reason Privilege_Withdrawn
        8. Certificate should revoked with the reason Remove_from_CRL
        9. Certificate revocation should failed with the reason Invalid Reason
    """
    userid = 'testuser4'
    subject = 'UID={},E={}@example.org,CN={}'.format(userid, userid,userid)
    cert_id = user_op.process_certificate_request(ansible_module, subject=subject)

    command = 'pki -d {} -c {} -p {} -P http -n "{}" ' \
              '{} {} --reason {}'.format(constants.NSSDB, constants.CLIENT_DATABASE_PASSWORD,
                                         constants.CA_HTTP_PORT, 'CA_AgentV', cmd, cert_id, reason)
    revoke_out = ansible_module.expect(command=command,
                                       responses={"Are you sure \(Y\/N\)?": "Y"})
    for result in revoke_out.values():
        if result['rc'] == 0:
            if reason == "Remove_from_CRL":
                assert "One or more certificates could not be unrevoked" in result['stdout']
                assert 'Could not revoke certificate "{}'.format(cert_id) in result['stdout']
            else:
                if reason in ['Certificate_Hold']:
                    assert 'Placed certificate "{}" on-hold'.format(cert_id) in result['stdout']
                else:
                    assert 'Revoked certificate "{}"'.format(cert_id) in result['stdout']
                assert 'Serial Number: {}'.format(cert_id) in result['stdout']
                assert 'Subject DN: {}'.format(subject) in result['stdout']
                assert 'Issuer DN: ' in result['stdout']
                assert 'Status: REVOKED' in result['stdout']
                assert 'Not Valid Before: ' in result['stdout']
                assert 'Not Valid After: ' in result['stdout']
                assert 'Revoked On:' in result['stdout']
                assert 'Revoked By: CA_AgentV' in result['stdout']
        else:
            assert 'Error: Invalid revocation reason: Invalid revocation reason' in result['stdout']


@pytest.mark.parametrize('reason', ('unspecified', 'Key_Compromise', 'CA_Compromise',
                                    'Affiliation_Changed', 'Superseded', 'Cessation_of_Operation',
                                    'Certificate_Hold', 'Privilege_Withdrawn', 'Remove_from_CRL',
                                    pytest.mark.xfail('Invalid_revocation_reason')))
def test_pki_cert_revoke_with_force_and_reason(ansible_module, reason):
    """
    :Title:
        Test pki ca-cert-revoke with force and different reasons unspecified,
        Key_Compromise,
        CA_Compromise, Affiliation_Changed, Superseded, Cessation_of_Operation, Certificate_Hold,
        Privilege_Withdrawn, Remove_from_CRL and with invalid Reason.
    :Description:
        Test pki ca-cert-revoke with force and different reasons unspecified, Key_Compromise,
        CA_Compromise, Affiliation_Changed, Superseded, Cessation_of_Operation, Certificate_Hold,
        Privilege_Withdrawn, Remove_from_CRL and with invalid Reason. Command should able to revoke
        the certificate with the specified reason.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-cert-revoke <serial_no> --force --reason unspecified
        2. Run pki ca-cert-revoke <serial_no> --force --reason Key_Compromise
        3. Run pki ca-cert-revoke <serial_no> --force --reason CA_Compromise
        4. Run pki ca-cert-revoke <serial_no> --force --reason Affiliation_Changed
        5. Run pki ca-cert-revoke <serial_no> --force --reason Cessation_of_Operation
        6. Run pki ca-cert-revoke <serial_no> --force --reason Certificate_Hold
        7. Run pki ca-cert-revoke <serial_no> --force --reason Privilege_Withdrawn
        8. Run pki ca-cert-revoke <serial_no> --force --reason Remove_from_CRL
        9. Run pki ca-cert-revoke <serial_no> --force --reason Invalid Reason.

    :Expectedresults:
        1. Certificate should revoked with the reason unspecified
        2. Certificate should revoked with the reason Key_Compromise
        3. Certificate should revoked with the reason CA_Compromise
        4. Certificate should revoked with the reason Affiliation_Changed
        5. Certificate should revoked with the reason Cessation_of_Operation
        6. Certificate should revoked with the reason Certificate_Hold
        7. Certificate should revoked with the reason Privilege_Withdrawn
        8. Certificate should revoked with the reason Remove_from_CRL
        9. Certificate revocation should failed with the reason Invalid Reason
    """
    userid = 'testuser5'
    subject = 'UID={},CN={}'.format(userid, userid,userid)
    cert_id = user_op.process_certificate_request(ansible_module, subject=subject)
    revoke_out = ansible_module.pki(cli=cmd,
                                    nssdb=constants.NSSDB,
                                    dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                    port=constants.CA_HTTP_PORT,
                                    certnick="'{}'".format('CA_AgentV'),
                                    extra_args=' {} --force --reason {}'.format(cert_id, reason))

    for result in revoke_out.values():
        if result['rc'] == 0:
            if reason == "Remove_from_CRL":
                assert "One or more certificates could not be unrevoked" in result['stdout']
                assert 'Could not revoke certificate "{}'.format(cert_id) in result['stdout']
            else:
                if reason in ['Certificate_Hold']:
                    assert 'Placed certificate "{}" on-hold'.format(cert_id) in result['stdout']
                else:
                    assert 'Revoked certificate "{}"'.format(cert_id) in result['stdout']
                assert 'Serial Number: {}'.format(cert_id) in result['stdout']
                assert 'Subject DN: {}'.format(subject) in result['stdout']
                assert 'Issuer DN: ' in result['stdout']
                assert 'Status: REVOKED' in result['stdout']
                assert 'Not Valid Before: ' in result['stdout']
                assert 'Not Valid After: ' in result['stdout']
                assert 'Revoked On:' in result['stdout']
                assert 'Revoked By: CA_AgentV' in result['stdout']
        else:
            assert 'Error: Invalid revocation reason: {}'.format(reason) in result['stderr']


def test_pki_cert_revoke_which_is_already_revoked(ansible_module):
    """
    :Title: Test pki ca-cert-revoke when certificate is already revoked.
    :Description:
        Test pki ca-cert-revoke should not able to revoke the certificate again when it
        is already revoked. It should able throw the message that it is already revoked.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Submit the certificate request for user.
        2. Request should get approve and certificate should be generated.
        3. Run pki ca-cert-revoke <cert_id> --force
        4. Run pki ca-cert-revoke <cert_id> --force again.
    :Expectedresults:
        1. Request should successfully get submitted.
        2. Certificate should get generated, and get the certificate_id.
        3. Certificate should get revoked.
        4. It should throw an error message that certificate is already revoked.
    """
    userid = 'testuser6'
    subject = 'UID={},E={}@example.org,CN={}'.format(userid, userid,userid)
    cert_id = user_op.process_certificate_request(ansible_module, subject=subject)
    revoke_out = ansible_module.pki(cli=cmd,
                                    nssdb=constants.NSSDB,
                                    dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                    port=constants.CA_HTTP_PORT,
                                    certnick="'{}'".format('CA_AgentV'),
                                    extra_args=' {} --force'.format(cert_id))
    for host, result in revoke_out.items():
        if result['rc'] == 0:
            assert 'Revoked certificate "{}"'.format(cert_id) in result['stdout']
            assert 'Serial Number: {}'.format(cert_id) in result['stdout']
            assert 'Subject DN: {}'.format(subject) in result['stdout']
            assert 'Issuer DN: ' in result['stdout']
            assert 'Status: REVOKED' in result['stdout']
            assert 'Not Valid Before: ' in result['stdout']
            assert 'Not Valid After: ' in result['stdout']
            assert 'Revoked On:' in result['stdout']
            assert 'Revoked By: CA_AgentV' in result['stdout']
        else:
            pytest.xfail("Failed to run pki {} {}".format(cmd, cert_id))

    revoke_again = ansible_module.pki(cli=cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.CA_HTTP_PORT,
                                      certnick="'{}'".format('CA_AgentV'),
                                      extra_args='{} --force'.format(cert_id))
    for host, result in revoke_again.items():
        if result['rc'] == 0:
            pytest.xfail("Failed to run pki {} {} when certificate "
                         "already revoked.".format(cmd, cert_id))
        else:
            assert 'BadRequestException: certificate #{} has ' \
                   'already been revoked'.format(cert_id.split('x')[1]) in result['stderr']


def test_pki_cert_revoke_which_is_expired(ansible_module):
    """
    :Title: Test pki ca-cert-revoke when certificate is expired.
    :Description:
        Test pki ca-cert-revoke should not able to revoke the certificate again when it
        is expired. It should able throw the message that it is expired.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Submit the certificate request for user.
        2. Request should get approve and certificate should be generated.
        3. Make sure that certificate is expired
        4. Run pki ca-cert-revoke <cert_id> --force.
    :Expectedresults:
        1. Request should successfully get submitted.
        2. Certificate should get generated, and get the certificate_id.
        3. Certificate should get expired.
        4. It should throw an error message that certificate is already revoked.
    """
    userid = 'testuser7'
    subject = 'UID={},E={}@example.org,CN={}'.format(userid, userid,
                                                                                  userid)
    cert_id = user_op.process_certificate_request(ansible_module, subject=subject,
                                                  profile="caAgentFoobar")
    from time import sleep
    sleep(20)
    revoke_out = ansible_module.pki(cli=cmd,
                                    nssdb=constants.NSSDB,
                                    dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                    port=constants.CA_HTTP_PORT,
                                    certnick="'{}'".format('CA_AgentV'),
                                    extra_args=' {} --force'.format(cert_id))

    for host, result in revoke_out.items():
        if result['rc'] == 0:
            assert 'Revoked certificate "{}"'.format(cert_id) in result['stdout']
            assert 'Serial Number: {}'.format(cert_id) in result['stdout']
            assert 'Subject DN: {}'.format(subject) in result['stdout']
            assert 'Issuer DN: ' in result['stdout']
            assert 'Status: REVOKED' in result['stdout']
            assert 'Not Valid Before: ' in result['stdout']
            assert 'Not Valid After: ' in result['stdout']
            assert 'Revoked On:' in result['stdout']
            assert 'Revoked By: CA_AgentV' in result['stdout']
        else:
            pytest.xfail("Failed to run pki {} {}".format(cmd, cert_id))


def test_pki_cert_revoke_non_ca_signing_certificate(ansible_module):
    """
    :Title: Test pki ca-cert-revoke with --ca, certificate should be normal certificate.
    :Description:
        Test pki ca-cert-revoke with --ca, certificate should be normal certificate and it should
        throw an error certificate is not CA Signing certificate.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Submit the certificate request for user.
        2. Request should get approve and certificate should be generated.
        3. Run pki ca-cert-revoke <cert_id> --ca

    :Expectedresults:
        1. Request should successfully get submitted.
        2. Certificate should get generated, and get the certificate_id.
        3. Certificate should not get revoked, instead it throw an error message.
    """
    userid = 'testuser8'
    subject = 'UID={},E={}@example.org,CN={}'.format(userid, userid,userid)
    cert_id = user_op.process_certificate_request(ansible_module, subject=subject)
    command = 'pki -d {} -c {} -p {} -P http -n "{}" ' \
              '{} {} --ca --reason unspecified'.format(constants.NSSDB,
                                                       constants.CLIENT_DATABASE_PASSWORD,
                                                       constants.CA_HTTP_PORT, 'CA_AgentV',
                                                       cmd, cert_id)
    revoke_out = ansible_module.expect(command=command,
                                       responses={"Are you sure \(Y\/N\)?": "Y"})
    for host, result in revoke_out.items():
        if result['rc'] == 0:
            pytest.xfail("Failed to run pki {} {} --ca --reason unspecified".format(cmd, cert_id))
        else:
            assert "UnauthorizedException: Certificate {} is not a " \
                   "CA signing certificate".format(cert_id) in result['stdout']


def test_pki_cert_revoke_non_ca_signing_certificate_with_force(ansible_module):
    """
    :Title: Test pki ca-cert-revoke with --force --ca, certificate should be
                normal certificate.
    :Description:
        Test pki ca-cert-revoke with --ca, certificate should be normal certificate and it should
        throw an error certificate is not CA Signing certificate.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Submit the certificate request for user.
        2. Request should get approve and certificate should be generated.
        3. Run pki ca-cert-revoke <cert_id> --ca --force
    :Expectedresults:
        1. Request should successfully get submitted.
        2. Certificate should get generated, and get the certificate_id.
        3. Certificate should not get revoked, instead it throw an error message.
    """
    userid = 'testuser9'
    subject = 'UID={},E={}@example.org,CN={}'.format(userid, userid,
                                                                                  userid)
    cert_id = user_op.process_certificate_request(ansible_module, subject=subject)

    revoke_out = ansible_module.pki(cli=cmd,
                                    nssdb=constants.NSSDB,
                                    dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                    port=constants.CA_HTTP_PORT,
                                    certnick="'{}'".format('CA_AgentV'),
                                    extra_args=' {} --ca --force '
                                               '--reason unspecified'.format(cert_id))
    for host, result in revoke_out.items():
        if result['rc'] == 0:
            pytest.xfail("Failed to run pki {} {} --ca --reason unspecified".format(cmd, cert_id))
        else:
            assert "UnauthorizedException: Certificate {} is not a " \
                   "CA signing certificate".format(cert_id) in result['stderr']


def test_pki_cert_revoke_ca_signing_cert_with_force(ansible_module):
    """
    :Title: Test pki ca-cert-revoke 0x1 --ca --force --reason Certificate_Hold,
            Revoke the CA Signing certificate.
    :Description:
        Test pki ca-cert-revoke 0x1 --ca --force --reason Certificate_Hold, It should revoke
        the CA signing certificate.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-cert-revoke 0x1 --ca --reason Certificate_Hold
        2. Run pki ca-cert-release-hold 0x1 --force
    :Expectedresults:
        1. It should able to revoke the CA Signing Certificate.
        2. Release the certificate form the hold.
    """
    revoke_out = ansible_module.pki(cli=cmd,
                                    nssdb=constants.NSSDB,
                                    dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                    port=constants.CA_HTTP_PORT,
                                    certnick="'{}'".format('CA_AgentV'),
                                    extra_args='0x1 --ca --force --reason Certificate_Hold')
    for host, result in revoke_out.items():
        if result['rc'] == 0:
            assert 'Placed certificate "0x1" on-hold' in result['stdout']
            assert 'Serial Number: 0x1' in result['stdout']
            assert 'Subject DN: ' in result['stdout']
            assert 'Issuer DN: ' in result['stdout']
            assert 'Status: REVOKED' in result['stdout']
            assert 'Not Valid Before: ' in result['stdout']
            assert 'Not Valid After: ' in result['stdout']
            assert 'Revoked On:' in result['stdout']
            assert 'Revoked By: CA_AgentV' in result['stdout']
        else:
            pytest.xfail("Failed to run pki {} {}".format(cmd, '0x1'))
    revoke_out = ansible_module.pki(cli='ca-cert-release-hold',
                                    nssdb=constants.NSSDB,
                                    dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                    port=constants.CA_HTTP_PORT,
                                    certnick="'{}'".format('CA_AgentV'),
                                    extra_args='0x1 --force')
    for host, result in revoke_out.items():
        if result['rc'] == 0:
            assert 'Placed certificate "0x1" off-hold' in result['stdout']
            assert 'Serial Number: 0x1' in result['stdout']
            assert 'Subject DN: ' in result['stdout']
            assert 'Issuer DN: ' in result['stdout']
            assert 'Status: VALID' in result['stdout']
            assert 'Not Valid Before: ' in result['stdout']
            assert 'Not Valid After: ' in result['stdout']
        else:
            pytest.xfail("Failed to place the certificate off-hold '0x1'.")


def test_pki_cert_revoke_ca_signing_cert(ansible_module):
    """
    :Title: Test pki ca-cert-revoke 0x1 --ca --reason Certificate_Hold, Revoke the CA Signing certificate.
    :Description:
        Test pki ca-cert-revoke 0x1 --ca --reason Certificate_Hold, It should revoke the CA signing
        certificate.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-cert-revoke 0x1 --ca --reason Certificate_Hold
        2. Run pki ca-cert-release-hold 0x1 --force
    :Expectedresults:
        1. It should able to revoke the CA Signing Certificate.
        2. Release the certificate form the hold.
    """

    cert_id = '0x1'
    command = 'pki -d {} -c {} -p {} -P http -n "{}" ' \
              '{} {} --ca --reason Certificate_Hold'.format(constants.NSSDB,
                                                            constants.CLIENT_DATABASE_PASSWORD,
                                                            constants.CA_HTTP_PORT, 'CA_AgentV',
                                                            cmd, cert_id)
    revoke_out = ansible_module.expect(command=command,
                                       responses={"Are you sure \(Y\/N\)?": "Y"})

    for result in revoke_out.values():
        if result['rc'] == 0:
            assert 'Placed certificate "0x1" on-hold' in result['stdout']
            assert 'Serial Number: 0x1' in result['stdout']
            assert 'Subject DN: ' in result['stdout']
            assert 'Issuer DN: ' in result['stdout']
            assert 'Status: REVOKED' in result['stdout']
            assert 'Not Valid Before: ' in result['stdout']
            assert 'Not Valid After: ' in result['stdout']
            assert 'Revoked On:' in result['stdout']
            assert 'Revoked By: CA_AgentV' in result['stdout']
        else:
            pytest.xfail("Failed to run pki {} {}".format(cmd, '0x1'))
    revoke_out = ansible_module.pki(cli='ca-cert-release-hold',
                                    nssdb=constants.NSSDB,
                                    dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                    port=constants.CA_HTTP_PORT,
                                    certnick="'{}'".format('CA_AgentV'),
                                    extra_args='0x1 --force')
    for result in revoke_out.values():
        if result['rc'] == 0:
            assert 'Placed certificate "0x1" off-hold' in result['stdout']
            assert 'Serial Number: 0x1' in result['stdout']
            assert 'Subject DN: ' in result['stdout']
            assert 'Issuer DN: ' in result['stdout']
            assert 'Status: VALID' in result['stdout']
            assert 'Not Valid Before: ' in result['stdout']
            assert 'Not Valid After: ' in result['stdout']
        else:
            pytest.xfail("Failed to place the certificate off-hold '0x1'.")


@pytest.mark.parametrize('user, error', (('CA_AgentE',
                                          ['IOException: SocketException cannot write on socket',
                                           'FATAL: SSL alert received: CERTIFICATE_EXPIRED']),
                                         ('CA_AgentR', ['PKIException: Unauthorized']),
                                         ('CA_AuditR', ['PKIException: Unauthorized'])))
def test_pki_cert_revoke_with_different_audit_and_agent_cert(ansible_module, user, error):
    """
    :Title: Test pki ca-cert-revoke with different Audit and Agent certificates.
    :Description:
        This test will test ca-cert-revoke with different Audit and Agent certificates.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Run pki -n CA_AgentE ca-cert-revoke <cert_id>
        2. Run pki -n CA_AgentR ca-cert-revoke <cert_id>
        3. Run pki -n CA_AuditR ca-cert-revoke <cert_id>
    :Expectedresults:
        1. It should able to throw the error CERTIFICATE_EXPIRED.
        2. It should able to throw the error PKIException: Unauthorized
        3. It should able to throw the error Authorization Error
    """
    userid = 'testuser10'
    subject = 'UID={},E={}@example.org,CN={}'.format(userid, userid,
                                                                                  userid)
    cert_id = user_op.process_certificate_request(ansible_module, subject=subject)

    revoke_out = ansible_module.pki(cli=cmd,
                                    nssdb=constants.NSSDB,
                                    dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                    port=constants.CA_HTTP_PORT,
                                    certnick="'{}'".format(user),
                                    extra_args=' {} --force'.format(cert_id))

    for host, result in revoke_out.items():
        if result['rc'] == 0:
            pytest.xfail("Failed to run pki -n {} {} {}".format(user, cmd, cert_id))
        else:
            for e in error:
                assert e in result['stderr']
