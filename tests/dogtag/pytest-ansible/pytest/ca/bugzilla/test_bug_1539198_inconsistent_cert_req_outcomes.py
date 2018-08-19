#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Bug 1539198 - Inconsistent CERT_REQUEST_PROCESSED outcomes
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Sumedh Sidhaye <ssidhaye@redhat.com>
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
import os
import sys
import re
import tempfile

try:
    from pki.testlib.common import constants
except Exception:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

def test_bug_1539198_inconsistent_cert_req_outcomes(ansible_module):
    """
    :id: fdb0230f-e8be-49c9-8170-401515c2acf8

    :Title: Bug 1539198 - Inconsistent CERT_REQUEST_PROCESSED outcomes

    :Description: Bug 1539198 - Inconsistent CERT_REQUEST_PROCESSED outcomes

    :Requirement: Audit Logging

    :Setup:
        1. Setup SSL on the DS instance
        2. Subsystems should point to the LDAPS port

    :Steps:
        1. Generate a certificate request
        2. Reject a certificate request
        3. Cancel a certificate request

    :Expectedresults:
        1. Certificate request is successfully submitted to CA

        2. On Rejecting a certificate request the following log event is generated
        0.http-bio-8443-exec-10 - [15/Feb/2018:00:34:32 EST] [14] [6] \
        [AuditEvent=CERT_REQUEST_PROCESSED][SubjectID=caadmin][Outcome=Failure]\
        [ReqID=20][InfoName=rejectReason][InfoValue=<null>] certificate request processed

        3. On Cancelling a certificate request the following log event is generated
        0.http-bio-8443-exec-10 - [15/Feb/2018:00:35:25 EST] [14] [6] \
        [AuditEvent=CERT_REQUEST_PROCESSED][SubjectID=caadmin][Outcome=Failure]\
        [ReqID=19][InfoName=cancelReason][InfoValue=<null>] certificate request processed

    :Automated: No

    :CaseComponent: \-
    """
    temp_dir = tempfile.mkdtemp()

    client_init_output = ansible_module.pki(
        cli='client-init',
        nssdb=temp_dir,
        protocol='http',
        port=constants.CA_HTTP_PORT,
    )
    for result in client_init_output.values():
        assert "Client initialized" in result['stdout']

    pkcs12_import_output = ansible_module.pki(
        cli='client-cert-import',
        nssdb=temp_dir,
        extra_args='--pkcs12 %s/ca_admin_cert.p12 --pkcs12-password %s'
        % (constants.CA_CLIENT_DIR, constants.CLIENT_DATABASE_PASSWORD),
        protocol='http',
        port=constants.CA_HTTP_PORT,
        )
    for result in pkcs12_import_output.values():
        assert "Imported certificates from PKCS #12 file" in result['stdout']

    # Approve a certificate request and check audit log
    cert_req_output = ansible_module.pki(
        cli='client-cert-request',
        nssdb=temp_dir,
        protocol='http',
        port=constants.CA_HTTP_PORT,
        extra_args='uid=foobar1'
    )

    request_id = None
    for result in cert_req_output.values():
        assert "Submitted certificate request" in result['stdout']
        assert "Type: enrollment" in result['stdout']
        assert "Request Status: pending" in result['stdout']
        assert "Operation Result: success" in result['stdout']
        request_id = re.findall('Request ID\: [0-9]+', result['stdout'])
        request_id = request_id[0].split(':')[1].strip()

    cert_approve_output = ansible_module.pki(
        cli='cert-request-review',
        nssdb=temp_dir,
        protocol='http',
        port=constants.CA_HTTP_PORT,
        extra_args='%s --action approve' % request_id
    )
    for result in cert_approve_output.values():
        assert "Approved certificate request %s" % request_id in result['stdout']
        assert "Request ID: %s" % request_id in result['stdout']
        assert "Type: enrollment" in result['stdout']
        assert "Request Status: complete" in result['stdout']
        assert "Operation Result: success" in result['stdout']
        assert "Certificate ID:" in result['stdout']

    audit_log_output = ansible_module.command('tail -n 100 /var/log/pki/{}/ca/signedAudit/ca_audit'\
                                              .format(constants.CA_INSTANCE_NAME))
    for result in audit_log_output.values():
        assert "[AuditEvent=CERT_REQUEST_PROCESSED][SubjectID=%s][Outcome=Success][ReqID=%s]"\
               % (constants.CA_ADMIN_USERNAME, request_id) in result['stdout']

    # Reject a certificate request and check audit log
    cert_req_output = ansible_module.pki(
        cli='client-cert-request',
        nssdb=temp_dir,
        protocol='http',
        port=constants.CA_HTTP_PORT,
        extra_args='uid=foobar2'
    )

    request_id = None
    for result in cert_req_output.values():
        assert "Submitted certificate request" in result['stdout']
        assert "Type: enrollment" in result['stdout']
        assert "Request Status: pending" in result['stdout']
        assert "Operation Result: success" in result['stdout']
        request_id = re.findall('Request ID\: [0-9]+', result['stdout'])
        request_id = request_id[0].split(':')[1].strip()

    cert_reject_output = ansible_module.pki(
        cli='cert-request-review',
        nssdb=temp_dir,
        protocol='http',
        port=constants.CA_HTTP_PORT,
        extra_args='%s --action reject' % request_id
    )
    for result in cert_reject_output.values():
        assert "Rejected certificate request %s" % request_id in result['stdout']
        assert "Request ID: %s" % request_id in result['stdout']
        assert "Type: enrollment" in result['stdout']
        assert "Request Status: rejected" in result['stdout']
        assert "Operation Result: success" in result['stdout']

    audit_log_output = ansible_module.command('tail -n 100 /var/log/pki/{}/ca/signedAudit/ca_audit'\
                                              .format(constants.CA_INSTANCE_NAME))
    for result in audit_log_output.values():
        assert "[AuditEvent=CERT_REQUEST_PROCESSED][SubjectID=%s][Outcome=Failure][ReqID=%s][InfoName=rejectReason][InfoValue=<null>] certificate request processed"\
               % (constants.CA_ADMIN_USERNAME, request_id) in result['stdout']

    # Cancel a certificate request and check audit log
    cert_req_output = ansible_module.pki(
        cli='client-cert-request',
        nssdb=temp_dir,
        protocol='http',
        port=constants.CA_HTTP_PORT,
        extra_args='uid=foobar3'
    )

    request_id = None
    for result in cert_req_output.values():
        assert "Submitted certificate request" in result['stdout']
        assert "Type: enrollment" in result['stdout']
        assert "Request Status: pending" in result['stdout']
        assert "Operation Result: success" in result['stdout']
        request_id = re.findall('Request ID\: [0-9]+', result['stdout'])
        request_id = request_id[0].split(':')[1].strip()

    cert_cancel_output = ansible_module.pki(
        cli='cert-request-review',
        nssdb=temp_dir,
        protocol='http',
        port=constants.CA_HTTP_PORT,
        extra_args='%s --action cancel' % request_id
    )
    for result in cert_cancel_output.values():
        assert "Canceled certificate request %s" % request_id in result['stdout']
        assert "Request ID: %s" % request_id in result['stdout']
        assert "Type: enrollment" in result['stdout']
        assert "Request Status: canceled" in result['stdout']
        assert "Operation Result: success" in result['stdout']

    audit_log_output = ansible_module.command('tail -n 100 /var/log/pki/{}/ca/signedAudit/ca_audit'\
                                              .format(constants.CA_INSTANCE_NAME))
    for result in audit_log_output.values():
        assert "[AuditEvent=CERT_REQUEST_PROCESSED][SubjectID=%s][Outcome=Failure][ReqID=%s][InfoName=cancelReason][InfoValue=<null>] certificate request processed"\
               % (constants.CA_ADMIN_USERNAME, request_id) in result['stdout']