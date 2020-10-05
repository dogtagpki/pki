#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Bug 1750277 - missing audit event for CS acting as TLS client
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Pritam Singh <prisingh@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2020 Red Hat, Inc. All rights reserved.
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
import pytest
import os
import sys
import random
import time
import logging
from pki.testlib.common import loggingutils
from pki.testlib.common.utils import UserOperations
from pki.testlib.common.certlib import CertSetup

try:
    from pki.testlib.common import constants
except Exception:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

user_op = UserOperations(nssdb=constants.NSSDB)
log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
format_script_path = '/tmp/test_dir/token_format.txt'
enroll_script_path = '/tmp/test_dir/token_enroll.txt'
ldap_uadd_path = '/tmp/test_dir/ldap_user_add.cfg'


@pytest.mark.setup
def test_setup(ansible_module):
    """
    It creates NSSDB and import ca and tps admin cert.
    Add ldap user.
    """
    # Create nssdb
    cert_setup = CertSetup(nssdb=constants.NSSDB,
                           db_pass=constants.CLIENT_DATABASE_PASSWORD,
                           host='{}'.format(constants.MASTER_HOSTNAME),
                           port=constants.CA_HTTP_PORT,
                           nick="'{}'".format(constants.CA_ADMIN_NICK))
    cert_setup.create_certdb(ansible_module)
    cert_setup.import_ca_cert(ansible_module)
    cert_setup.import_admin_p12(ansible_module, 'ca')
    cert_setup.import_admin_p12(ansible_module, 'tps')

    # Update tpsclient format and enroll script.
    ansible_module.replace(path=format_script_path, regexp='CUID', replace=constants.CUID)
    ansible_module.replace(path=enroll_script_path, regexp='CUID', replace=constants.CUID)

    # Create ldap user
    log.info('Creating ldap user')
    uadd_cmd = 'ldapadd -x -D "cn=directory manager" -h {} -p {} -w {} -f {}'.format(constants.MASTER_HOSTNAME,
                                                                                     constants.LDAP_PORT,
                                                                                     constants.LDAP_PASSWD,
                                                                                     ldap_uadd_path)
    cmd = ansible_module.command(uadd_cmd)
    for result in cmd.values():
        if result['rc'] == 0:
            assert 'adding new entry' in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            assert result['rc'] > 0
            log.error("Failed to run : {}".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


def test_bug_1750277_missing_audit_event_tls_client(ansible_module):
    """
    :Title: Bug 1750277 - missing audit event for CS acting as TLS client

    :Description: This automation tests for missing audit event for CS acting as TLS client

    :Requirement:

    :CaseComponent: \-

    :Steps:
            1. Install subsystem with TLS enabled LDAP.
            2. Check for 'CLIENT_ACCESS_SESSION_ESTABLISH' audit event in TMS subsystem audit log
            3. Bring KRA down and performed CRMF and try to approve the generated cert request
            4. Bring KRA in working state & perform CRMF again and try to approve the cert request
            5. Bring LDAP server down and it CA server should generate log for communication attempt to LDAP server
            6. Enroll token and check for TPS -> TKS, TPS -> CA, TPS -> KRA connectivity logs.

    :Expectedresults:
            1. Subsystem should successfully installed with TLS enabled in LDAP
            2. The 'CLIENT_ACCESS_SESSION_ESTABLISH' log should exist in subsystem's audit log
            3. It should generated Error and request should get rejected
            4. Cert should successfully get approved
            5. CA should tries to communicate with LDAP Server and it could be seen in CA audit log
            6. TPS should try to communicate with different subsystem over token enrollment

    :Automated: Yes
    """
    # 2. Check 'CLIENT_ACCESS_SESSION_ESTABLISH' in subsystem audit log
    subsystem = ['CA', 'KRA', 'OCSP', 'TKS', 'TPS']
    for i in subsystem:
        subsystem_audit = loggingutils.get_audit_log(ansible_module, i)
        cmd = ansible_module.shell("grep 'CLIENT_ACCESS_SESSION_ESTABLISH' {} | head -1".format(subsystem_audit))
        for result in cmd.values():
            if result['rc'] == 0:
                assert 'CLIENT_ACCESS_SESSION_ESTABLISH' in result['stdout']
                log.info("Successfully Found 'CLIENT_ACCESS_SESSION_ESTABLISH' in {}".format(i))
            else:
                assert result['rc'] > 0
                log.error(result['stdout'])
                log.error(result['stderr'])
                pytest.fail("Failed to grep 'CLIENT_ACCESS_SESSION_ESTABLISH' in {}".format(i))

    # 3. Bring down KRA, Perform CRMF and approve the request

    # Perform CRMF cert request
    subject = "UID=testuser{}".format(random.randint(111, 99999))
    request_id = user_op.create_certificate_request(ansible_module,
                                                    subject=subject,
                                                    request_type='crmf',
                                                    keysize='2048',
                                                    profile='caDualCert')

    # Bring KRA down
    ansible_module.command('systemctl stop pki-tomcatd@{}'.format(constants.KRA_INSTANCE_NAME))
    time.sleep(5)

    # Try to approve the request
    review_req = ansible_module.pki(cli='ca-cert-request-review',
                                    nssdb=constants.NSSDB,
                                    dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                    certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                    port=constants.CA_HTTP_PORT,
                                    extra_args='{} --action {}'.format(request_id, 'approve'))

    for result in review_req.values():
        log.info("Running : {}".format(result['cmd']))
        if result['rc'] > 0:
            assert 'BadRequestException: Request Sending DRM request ' \
                   'failed check KRA log for detail Rejected' in result['stderr']
            log.info('Successfully ran: {}'.format(result['cmd']))
        else:
            assert 'Approved certificate request' in result['stdout']
            log.error("Failed to run {}".format(result['cmd']))
            pytest.fail()

    # Observe 'CLIENT_ACCESS_SESSION_ESTABLISH' failure case in CA audit log
    ip = ansible_module.shell("hostname -i | awk '{print $3}'")
    ip_add = ip.keys()[0]
    audit_log = '[AuditEvent=CLIENT_ACCESS_SESSION_ESTABLISH][ClientHost={}]' \
                '[ServerHost={}][ServerPort={}][SubjectID=SYSTEM]' \
                '[Outcome=Failure][Info=connect:java.io.IOException: Couldnt make connection] ' \
                'access session failed to establish when Certificate ' \
                'System acts as client'.format(ip_add,
                                               constants.MASTER_HOSTNAME,
                                               constants.KRA_HTTPS_PORT)
    time.sleep(2)
    cmd = ansible_module.command('tail -n 20 {}'.format(loggingutils.get_audit_log(ansible_module, 'CA')))
    for result in cmd.values():
        if result['rc'] == 0:
            assert audit_log in result['stdout']
            log.info('Successfully found "CLIENT_ACCESS_SESSION_ESTABLISH" failure log in CA audit log')
        else:
            log.error('Error log not found')
            pytest.fail()

    # 4. Bring KRA up, request and approve cert
    ansible_module.command('systemctl start pki-tomcatd@{}'.format(constants.KRA_INSTANCE_NAME))

    # CRMF cert request
    subject = "UID=testuser{}".format(random.randint(111, 99999))
    request_id = user_op.create_certificate_request(ansible_module,
                                                    subject=subject,
                                                    request_type='crmf',
                                                    keysize='2048',
                                                    profile='caDualCert')

    # Approve the request
    review_req = ansible_module.pki(cli='ca-cert-request-review',
                                    nssdb=constants.NSSDB,
                                    dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                    certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                    port=constants.CA_HTTP_PORT,
                                    extra_args='{} --action {}'.format(request_id, 'approve'))

    for result in review_req.values():
        log.info("Running : {}".format(result['cmd']))
        if result['rc'] == 0:
            assert 'Request Status: complete' in result['stdout']
            assert 'Approved certificate request {}'.format(request_id) in result['stdout']
            log.info('Successfully ran: {}'.format(result['cmd']))
        else:
            assert result['rc'] > 0
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail("Failed to run {}".format(result['cmd']))
    time.sleep(5)

    # Assert the Session establish & terminated audit logs
    audit_log_establish = '[AuditEvent=CLIENT_ACCESS_SESSION_ESTABLISH][ClientHost={}]' \
                          '[ServerHost={}][ServerPort={}][SubjectID=SYSTEM]' \
                          '[Outcome=Success] ' \
                          'access session establish successfully when Certificate ' \
                          'System acts as client'.format(ip_add, ip_add, constants.KRA_HTTPS_PORT)
    audit_log_terminate = '[AuditEvent=CLIENT_ACCESS_SESSION_TERMINATED][ClientHost={}]' \
                          '[ServerHost={}][ServerPort={}][SubjectID=SYSTEM][Outcome=Success]' \
                          '[Info=CLOSE_NOTIFY] access session terminated when ' \
                          'Certificate System acts as client'.format(ip_add, ip_add, constants.KRA_HTTPS_PORT)
    cmd = ansible_module.command('tail -n 40 {}'.format(loggingutils.get_audit_log(ansible_module, 'CA')))
    for result in cmd.values():
        if result['rc'] == 0:
            assert audit_log_establish in result['stdout']
            assert audit_log_terminate in result['stdout']
            log.info('Successfully found Establish & Terminate log in CA audit log')
        else:
            log.error('Error log not found')
            pytest.fail()

    # 5. Bring LDAP Server down and check the audit log for CA -> LDAP
    ansible_module.command('systemctl stop dirsrv@{}'.format('topology-02-testingmaster'))
    time.sleep(2)

    # Check the audit log for CA -> LDAP connectivity
    audit_log = '[AuditEvent=CLIENT_ACCESS_SESSION_ESTABLISH][ClientHost={}]' \
                '[ServerHost={}][ServerPort={}][SubjectID=SYSTEM]' \
                '[Outcome=Failure][Info=connect:org.mozilla.jss.ssl.SSLSocketException: ' \
                'Unable to connect: (-5961) TCP connection reset by peer.] ' \
                'access session failed to establish ' \
                'when Certificate System acts as client'.format(ip_add, constants.MASTER_HOSTNAME, '2636')
    cmd = ansible_module.command('tail -n 10 {}'.format(loggingutils.get_audit_log(ansible_module, 'CA')))
    for result in cmd.values():
        if result['rc'] == 0:
            assert audit_log in result['stdout']
            log.info('Successfully found CA -> LDAP connection log in CA audit log')
        else:
            log.error('Error log not found')
            pytest.fail()

    # Revert the changes
    ansible_module.command('systemctl start dirsrv@{}'.format('topology-02-testingmaster'))

    # 6. Enroll token with tpsclient

    # Enroll the token with tpsclient enroll script
    log.info('Enroll a token')
    enroll_token = ansible_module.shell('tpsclient < {}'.format(enroll_script_path))
    for result in enroll_token.values():
        if result['rc'] == 1:
            assert "Result> Success - Operation 'ra_enroll' Success" in result['stdout']
            log.info('Successfully enrolled the token with : {}'.format(result['cmd']))
        else:
            assert result['rc'] > 1
            log.error('Failed to ran : {}'.format(result['cmd']))
            pytest.fail(result['stdout'])
            pytest.fail(result['stderr'])
    time.sleep(5)

    # Check audit logs for TPS -> TKS, TPS -> CA, TPS -> KRA communication
    tps_tks_log_establish = '[AuditEvent=CLIENT_ACCESS_SESSION_ESTABLISH][ClientHost={}]' \
                            '[ServerHost={}][ServerPort={}][SubjectID=SYSTEM]' \
                            '[Outcome=Success] access session establish successfully when ' \
                            'Certificate System acts as client'.format(ip_add, ip_add, constants.TKS_HTTPS_PORT)
    tps_tks_log_terminate = '[AuditEvent=CLIENT_ACCESS_SESSION_TERMINATED][ClientHost={}]' \
                            '[ServerHost={}][ServerPort={}][SubjectID=SYSTEM]' \
                            '[Outcome=Success][Info=CLOSE_NOTIFY] access session terminated when Certificate ' \
                            'System acts as client'.format(ip_add, ip_add, constants.TKS_HTTPS_PORT)
    tps_ca_log_establish = '[AuditEvent=CLIENT_ACCESS_SESSION_ESTABLISH][ClientHost={}]' \
                           '[ServerHost={}][ServerPort={}][SubjectID=SYSTEM]' \
                           '[Outcome=Success] access session establish successfully when ' \
                           'Certificate System acts as client'.format(ip_add, ip_add, constants.CA_HTTPS_PORT)
    tps_ca_log_terminate = '[AuditEvent=CLIENT_ACCESS_SESSION_TERMINATED][ClientHost={}]' \
                           '[ServerHost={}][ServerPort={}][SubjectID=SYSTEM]' \
                           '[Outcome=Success][Info=CLOSE_NOTIFY] access session terminated when ' \
                           'Certificate System acts as client'.format(ip_add, ip_add, constants.CA_HTTPS_PORT)
    tps_kra_log_establish = '[AuditEvent=CLIENT_ACCESS_SESSION_ESTABLISH][ClientHost={}]' \
                            '[ServerHost={}][ServerPort={}][SubjectID=SYSTEM]' \
                            '[Outcome=Success] access session establish successfully when ' \
                            'Certificate System acts as client'.format(ip_add, ip_add, constants.KRA_HTTPS_PORT)
    tps_kra_log_terminate = '[AuditEvent=CLIENT_ACCESS_SESSION_TERMINATED][ClientHost={}]' \
                            '[ServerHost={}][ServerPort={}][SubjectID=SYSTEM][Outcome=Success]' \
                            '[Info=CLOSE_NOTIFY] access session terminated when ' \
                            'Certificate System acts as client'.format(ip_add, ip_add, constants.KRA_HTTPS_PORT)
    cmd = ansible_module.command('tail -n 50 {}'.format(loggingutils.get_audit_log(ansible_module, 'TPS')))
    for result in cmd.values():
        if result['rc'] == 0:
            assert tps_tks_log_establish in result['stdout']
            assert tps_tks_log_terminate in result['stdout']
            assert tps_ca_log_establish in result['stdout']
            assert tps_ca_log_terminate in result['stdout']
            assert tps_kra_log_establish in result['stdout']
            assert tps_kra_log_terminate in result['stdout']
            log.info('Successfully found Establish & Terminate logs in TPS audit log')
        else:
            log.error('Logs not found')
            pytest.fail()

    # Clean up LDAP user and NSSDB
    ansible_module.command("ldapdelete -x -D 'cn=directory manager' -h {} -p {} -w {} '{}'".format(
        constants.MASTER_HOSTNAME, '3389', constants.CLIENT_DATABASE_PASSWORD, 'uid=jdoe,ou=people,dc=example,dc=org'))
    ansible_module.command('rm -rf {}'.format(constants.NSSDB))
