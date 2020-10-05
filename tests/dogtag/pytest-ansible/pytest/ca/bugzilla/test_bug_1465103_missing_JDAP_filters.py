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
CS_CFG_FILE = '/var/lib/pki/{}/ca/conf/CS.cfg'


@pytest.fixture(autouse=True)
def test_setup(ansible_module):
    stop_server = 'systemctl stop pki-tomcatd@{}'.format(constants.CA_INSTANCE_NAME)
    start_server = 'systemctl start pki-tomcatd@{}'.format(constants.CA_INSTANCE_NAME)
    filter = 'log.instance.SignedAudit.filters.CERT_REQUEST_PROCESSED=(|(InfoName=rejectReason)(InfoName=cancelReason))'
    stopped = ansible_module.shell(stop_server)
    for res in stopped.values():
        assert res['rc'] == 0

    ansible_module.lineinfile(path=CS_CFG_FILE.format(constants.CA_INSTANCE_NAME),
                              line=filter, insertafter="EOF")
    started = ansible_module.shell(start_server)
    for res in started.values():
        assert res['rc'] == 0

    yield
    stopped = ansible_module.shell(stop_server)
    for res in stopped.values():
        assert res['rc'] == 0
    new_filter = 'log.instance.SignedAudit.filters.CERT_REQUEST_PROCESSED=*'
    ansible_module.lineinfile(path=CS_CFG_FILE.format(constants.CA_INSTANCE_NAME),
                              regexp=new_filter, line="")

    started = ansible_module.shell(start_server)
    for res in started.values():
        assert res['rc'] == 0


@pytest.mark.skipif("topology != 2")
def test_missing_JDAP_filters(ansible_module):
    """
    :id: 898a8c4a-6223-4271-8708-705694903377'

    :Title: Bug 1465103 - Missing getter methods in JDAPFilter classes

    :Description: Bug 1465103 - Missing getter methods in JDAPFilter classes

    :Requirement: RHCS-REQ Audit Logging

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
               [AuditEvent=CERT_REQUEST_PROCESSED][SubjectID=caadmin][Outcome=Failure][ReqID=15][InfoName=cancelReason]
               [InfoValue=<null>] certificate request processed
               Only rejected request is shown in logs. Approved certificate requests are not shown in logs
            3. A certificate should be cancelled successfully
               [AuditEvent=CERT_REQUEST_PROCESSED][SubjectID=caadmin][Outcome=Failure][ReqID=15][InfoName=cancelReason]
               [InfoValue=<null>] certificate request processed
               Only cancelled request is shown in logs. Approved certificate requests are not shown in logs
    :Automated: Yes

    :CaseComponent: \-
    """
    log_file = '/var/log/pki/{}/ca/signedAudit/ca_audit'.format(constants.CA_INSTANCE_NAME)

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
            assert audit_log not in result['stdout']
            log.info("Log not found: {}".format(audit_log))
        else:
            log.error("Failed to create certificate request.")
            pytest.xfail()

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
