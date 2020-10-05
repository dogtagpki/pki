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
import logging
import os
import sys
import time
import pytest

from pki.testlib.common import utils

try:
    from pki.testlib.common import constants
except Exception:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
topology = int(constants.CA_INSTANCE_NAME.split("-")[-2])
userop = utils.UserOperations(nssdb=constants.NSSDB)


@pytest.mark.skipif("topology != 2")
@pytest.mark.parametrize('event', ['approve', 'cancel', 'reject'])
def test_bug_1539198_inconsistent_cert_req_outcomes(ansible_module, event):
    """
    :id: fdb0230f-e8be-49c9-8170-401515c2acf8

    :Title: Bug 1539198 - Inconsistent CERT_REQUEST_PROCESSED outcomes

    :Description: Bug 1539198 - Inconsistent CERT_REQUEST_PROCESSED outcomes

    :Requirement:

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
    log_file = '/var/log/pki/{}/ca/signedAudit/ca_audit'.format(constants.CA_INSTANCE_NAME)
    if event == 'approve':
        subject = 'UID=testuser1,CN=testuser1'
        time.sleep(10)
        req_id = userop.create_certificate_request(ansible_module, subject=subject)
        cert_id = userop.process_certificate_request(ansible_module, request_id=req_id, action='approve')
        assert req_id is not None
        audit_log = "[AuditEvent=CERT_REQUEST_PROCESSED][SubjectID={}]" \
                    "[Outcome=Success][ReqID={}]".format(constants.CA_ADMIN_USERNAME, req_id)

        audit_log_output = ansible_module.shell('tail -n 30 {}'.format(log_file))
        for result in audit_log_output.values():
            if result['rc'] == 0:
                assert audit_log in result['stdout']
                log.info("Log found: {}".format(audit_log))
            else:
                log.error("Failed to create certificate request.")
                pytest.xfail()

    elif event == 'reject':
        subject = 'UID=testuser2,CN=testuser2'
        req_id = userop.create_certificate_request(ansible_module, subject=subject)
        cert_id = userop.process_certificate_request(ansible_module, request_id=req_id, action='reject')
        assert req_id is not None
        audit_log = "[AuditEvent=CERT_REQUEST_PROCESSED][SubjectID={}][Outcome=Failure][ReqID={}]" \
                    "[InfoName=rejectReason][InfoValue=<null>] certificate " \
                    "request processed".format(constants.CA_ADMIN_USERNAME, req_id)

        audit_log_output = ansible_module.shell('tail -n 30 {}'.format(log_file))
        for result in audit_log_output.values():
            if result['rc'] == 0:
                assert audit_log in result['stdout']
                log.info("Log found: {}".format(audit_log))
            else:
                log.error("Failed to create certificate request.")
                pytest.xfail()
    elif event == 'cancel':
        subject = 'UID=testuser3,CN=testuser3'
        req_id = userop.create_certificate_request(ansible_module, subject=subject)
        cert_id = userop.process_certificate_request(ansible_module, request_id=req_id, action='cancel')
        assert req_id is not None
        audit_log = "[AuditEvent=CERT_REQUEST_PROCESSED][SubjectID={}][Outcome=Failure][ReqID={}]" \
                    "[InfoName=cancelReason][InfoValue=<null>] " \
                    "certificate request processed".format(constants.CA_ADMIN_USERNAME, req_id)
        audit_log_output = ansible_module.shell('tail -n 30 {}'.format(log_file))
        for result in audit_log_output.values():
            if result['rc'] == 0:
                assert audit_log in result['stdout']
                log.info("Log found: {}".format(audit_log))
            else:
                log.error("Failed to create certificate request.")
                pytest.xfail()
