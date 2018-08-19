#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Bug 1465103 - Missing getter methods in JDAPFilter classes
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

import pytest

try:
    from pki.testlib.common import constants
except Exception:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants


@pytest.mark.ansible_playbook_setup('enableAuditEventFilter.yml')
@pytest.mark.setup
def test_setup(ansible_playbook):
    pass

def test_missing_JDAP_filters(ansible_module):
    """
    :id: 898a8c4a-6223-4271-8708-705694903377'

    :Title: Bug 1465103 - Missing getter methods in JDAPFilter classes

    :Description: Bug 1465103 - Missing getter methods in JDAPFilter classes

    :Requirement: Audit Logging

    :Setup:
        Use subsystems setup via ansible playbooks

    :Steps:
            1. Add the following line in CA's CS.cfg
               log.instance.SignedAudit.filters.CERT_REQUEST_PROCESSED=(|(InfoName=rejectReason)(InfoName=cancelReason))
            2. Reject a certificate request
            3. Cancel a certificate request

    :Expectedresults:
            1. After adding the filter in CS.cfg CA instance should be restarted successfully
            2. A certificate should be rejected successfully and the logs should be similar to below
               root@csqa4-guest01 ~ # grep -nr "\[AuditEvent\=CERT_REQUEST_PROCESSED\]" /var/log/pki/<instance_name>/ca/signedAudit/ca_audit
               45:0.http-bio-8443-exec-16 - [03/Jan/2018:23:46:08 EST] [14] [6] [AuditEvent=CERT_REQUEST_PROCESSED][SubjectID=caadmin][Outcome=Success][ReqID=7][CertSerialNum=175797671] certificate request processed
               52:0.http-bio-8443-exec-20 - [03/Jan/2018:23:46:11 EST] [14] [6] [AuditEvent=CERT_REQUEST_PROCESSED][SubjectID=caadmin][Outcome=Success][ReqID=8][CertSerialNum=25082264] certificate request processed
               59:0.http-bio-8443-exec-24 - [03/Jan/2018:23:46:14 EST] [14] [6] [AuditEvent=CERT_REQUEST_PROCESSED][SubjectID=caadmin][Outcome=Success][ReqID=9][CertSerialNum=78183912] certificate request processed
               69:0.http-bio-8443-exec-4 - [03/Jan/2018:23:46:17 EST] [14] [6] [AuditEvent=CERT_REQUEST_PROCESSED][SubjectID=caadmin][Outcome=Success][ReqID=10][CertSerialNum=261210011] certificate request processed
               76:0.http-bio-8443-exec-10 - [03/Jan/2018:23:46:20 EST] [14] [6] [AuditEvent=CERT_REQUEST_PROCESSED][SubjectID=caadmin][Outcome=Success][ReqID=11][CertSerialNum=245038855] certificate request processed
               83:0.http-bio-8443-exec-18 - [03/Jan/2018:23:46:21 EST] [14] [6] [AuditEvent=CERT_REQUEST_PROCESSED][SubjectID=caadmin][Outcome=Success][ReqID=12][CertSerialNum=195767496] certificate request processed
               165:0.http-bio-8443-exec-5 - [03/Jan/2018:23:58:56 EST] [14] [6] [AuditEvent=CERT_REQUEST_PROCESSED][SubjectID=caadmin][Outcome=Success][ReqID=13][CertSerialNum=240995390] certificate request processed
               248:0.http-bio-8443-exec-13 - [04/Jan/2018:01:20:50 EST] [14] [6] [AuditEvent=CERT_REQUEST_PROCESSED][SubjectID=caadmin][Outcome=Failure][ReqID=15][InfoName=cancelReason][InfoValue=<null>] certificate request processed
               Only rejected request is shown in logs. Approved certificate requests are not shown in logs
            3. A certificate should be cancelled successfully
               root@csqa4-guest01 ~ # grep -nr "\[AuditEvent\=CERT_REQUEST_PROCESSED\]" /var/log/pki/<instance_name>/ca/signedAudit/ca_audit
               45:0.http-bio-8443-exec-16 - [03/Jan/2018:23:46:08 EST] [14] [6] [AuditEvent=CERT_REQUEST_PROCESSED][SubjectID=caadmin][Outcome=Success][ReqID=7][CertSerialNum=175797671] certificate request processed
               52:0.http-bio-8443-exec-20 - [03/Jan/2018:23:46:11 EST] [14] [6] [AuditEvent=CERT_REQUEST_PROCESSED][SubjectID=caadmin][Outcome=Success][ReqID=8][CertSerialNum=25082264] certificate request processed
               59:0.http-bio-8443-exec-24 - [03/Jan/2018:23:46:14 EST] [14] [6] [AuditEvent=CERT_REQUEST_PROCESSED][SubjectID=caadmin][Outcome=Success][ReqID=9][CertSerialNum=78183912] certificate request processed
               69:0.http-bio-8443-exec-4 - [03/Jan/2018:23:46:17 EST] [14] [6] [AuditEvent=CERT_REQUEST_PROCESSED][SubjectID=caadmin][Outcome=Success][ReqID=10][CertSerialNum=261210011] certificate request processed
               76:0.http-bio-8443-exec-10 - [03/Jan/2018:23:46:20 EST] [14] [6] [AuditEvent=CERT_REQUEST_PROCESSED][SubjectID=caadmin][Outcome=Success][ReqID=11][CertSerialNum=245038855] certificate request processed
               83:0.http-bio-8443-exec-18 - [03/Jan/2018:23:46:21 EST] [14] [6] [AuditEvent=CERT_REQUEST_PROCESSED][SubjectID=caadmin][Outcome=Success][ReqID=12][CertSerialNum=195767496] certificate request processed
               165:0.http-bio-8443-exec-5 - [03/Jan/2018:23:58:56 EST] [14] [6] [AuditEvent=CERT_REQUEST_PROCESSED][SubjectID=caadmin][Outcome=Success][ReqID=13][CertSerialNum=240995390] certificate request processed
               248:0.http-bio-8443-exec-13 - [04/Jan/2018:01:20:50 EST] [14] [6] [AuditEvent=CERT_REQUEST_PROCESSED][SubjectID=caadmin][Outcome=Failure][ReqID=15][InfoName=cancelReason][InfoValue=<null>] certificate request processed
               Only cancelled request is shown in logs. Approved certificate requests are not shown in logs
    :Automated: Yes

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
        extra_args='uid=foobar1 --profile caDualCert'
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
               % (constants.CA_ADMIN_USERNAME, request_id) not in result['stdout']

    # Reject a certificate request and check audit log
    cert_req_output = ansible_module.pki(
        cli='client-cert-request',
        nssdb=temp_dir,
        protocol='http',
        port=constants.CA_HTTP_PORT,
        extra_args='uid=foobar2 --profile caDualCert'
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
        assert "[AuditEvent=CERT_REQUEST_PROCESSED][SubjectID=%s][Outcome=Success][ReqID=%s]" \
               % (constants.CA_ADMIN_USERNAME, request_id) not in result['stdout']
        assert "[AuditEvent=CERT_REQUEST_PROCESSED][SubjectID=%s][Outcome=Failure][ReqID=%s][InfoName=rejectReason][InfoValue=<null>] certificate request processed"\
               % (constants.CA_ADMIN_USERNAME, request_id) in result['stdout']

    # Cancel a certificate request and check audit log
    cert_req_output = ansible_module.pki(
        cli='client-cert-request',
        nssdb=temp_dir,
        protocol='http',
        port=constants.CA_HTTP_PORT,
        extra_args='uid=foobar3 --profile caDualCert'
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
        assert "[AuditEvent=CERT_REQUEST_PROCESSED][SubjectID=%s][Outcome=Success][ReqID=%s]" \
               % (constants.CA_ADMIN_USERNAME, request_id) not in result['stdout']
        assert "[AuditEvent=CERT_REQUEST_PROCESSED][SubjectID=%s][Outcome=Failure][ReqID=%s][InfoName=cancelReason][InfoValue=<null>] certificate request processed"\
               % (constants.CA_ADMIN_USERNAME, request_id) in result['stdout']