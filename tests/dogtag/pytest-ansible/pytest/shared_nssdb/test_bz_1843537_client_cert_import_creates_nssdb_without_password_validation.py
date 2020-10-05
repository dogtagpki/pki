#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Automation of 1843537 - Able to Perform PKI CLI operations
#                like cert request and approval without NSSDB password
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
import sys
import os
import logging
import pytest
import re

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants
log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)


def test_bz_1843537_client_cert_import_creates_nssdb_without_pwd_validation(ansible_module):
    """
    :Title: Test bz_1843537 client cert import creates nssdb without password validation
    :Description: Test bz_1843537 client cert import creates nssdb without password validation
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Create NSSDB with client-cert-import and import certificate i.e
        # pki -d /tmp/nssdb -c SECret.123 -P http -p 20080 client-cert-import --ca-server RootCA
        # pki -d /tmp/nssdb -c SECret.123 -P http -p 20080 client-cert-import --pkcs12
         /opt/topology-02-CA/ca_admin_cert.p12 --pkcs12-password SECret.123
        2. Try to perform Cert Request and Approval with and without NSSDB Password:
        # pki -d /tmp/nssdb -P http -p 20080 client-cert-request 'uid=testday'
        # pki -d /tmp/nssdb -c SECret.123 -P http -p 20080 client-cert-request 'uid=testday'
    :ExpectedResults:
        1. It should create NSSDB with client-cert-import
        2. It should generate error in while creating CSR without nssdb password
        3. It should process the cert request and approval with nssdb password.
    """
    # Create NSSDB with client-cert-import
    tmp_nssdb = '/tmp/nssdb'
    log.info('Creating NSSDB at {}'.format(tmp_nssdb))
    cmd = ansible_module.pki(cli="client-cert-import",
                                 nssdb=tmp_nssdb,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 protocol='http',
                                 port=constants.CA_HTTP_PORT,
                                 extra_args='--ca-server {}'.format('RootCA'))
    for result in cmd.values():
        if result['rc'] == 0:
            log.info('Successfully Created NSSDB at {}'.format(tmp_nssdb))
        else:
            pytest.fail('Failed to create NSSDB at {}'.format(tmp_nssdb))

    # Import CA Admin Certificate
    log.info('Importing CA Admin Certificate')
    cmd = ansible_module.pki(cli="client-cert-import",
                                 nssdb=tmp_nssdb,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 protocol='http',
                                 port=constants.CA_HTTP_PORT,
                                 extra_args='--pkcs12 {}/ca_admin_cert.p12 --pkcs12-password {}'.format(
                                     constants.CA_CLIENT_DIR, constants.CA_PASSWORD))
    for result in cmd.values():
        if result['rc'] == 0:
            assert 'Imported certificates from PKCS #12 file' in result['stdout']
            log.info('Successfully imported CA Admin cert')
        else:
            pytest.fail('Failed to import CA Admin Cert')

    # Perform Cert request without NSSDB password
    log.info('Requesting Certificate without NSSDB password')
    cmd = ansible_module.command('pki -d {} -P http -p {} client-cert-request "uid={}"'.format(
        tmp_nssdb, constants.CA_HTTP_PORT, 'testcert'))
    for result in cmd.values():
        if result['rc'] > 0:
            assert 'ERROR: Unable to generate CSR:' in result['stderr']
            log.info('Success: Failed to create cert request without NSSDB password')
        else:
            assert result['rc'] == 0
            log.error('Failure: Certificate requested successfully without NSSDB pwd')
            pytest.fail('Bz: https://bugzilla.redhat.com/show_bug.cgi?id=1843537')

    # Perform Cert request with NSSDB password
    request_id = []
    log.info('Requesting Certificate with NSSDB password')
    cmd = ansible_module.pki(cli="client-cert-request",
                                 nssdb=tmp_nssdb,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 protocol='http',
                                 port=constants.CA_HTTP_PORT,
                                 extra_args='uid="{}"'.format('testcert'))
    for result in cmd.values():
        if result['rc'] == 0:
            assert 'Request Status: pending' in result['stdout']
            r_id = re.findall("Request ID:.*", result['stdout'])
            for i in r_id:
                request_id.append(i.split(":")[1].strip())
            log.info('Successfully created certificate request with NSSDB pwd')
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail('Failed to create cert request with NSSDB pwd')

    # Approve cert request with NSSDB pwd
    log.info('Approving cert request with NSSDB password')
    for i in request_id:
        cmd = 'pki -d {} -c {} -P http -p {} -n "{}" ca-cert-request-approve {}'.format(tmp_nssdb,
                                                                    constants.CLIENT_DATABASE_PASSWORD,
                                                                    constants.CA_HTTP_PORT,
                                                                    constants.CA_ADMIN_NICK, i)
        cert_res = ansible_module.expect(command=cmd, responses={"Are you sure (y/N)?": "y"})
        for result in cert_res.values():
            if result['rc'] == 0:
                assert 'Approved certificate request {}'.format(i) in result['stdout']
                assert 'Request Status: complete' in result['stdout']
                log.info('Successfully Approved cert request with NSSDB pwd')
            else:
                log.error(result['stdout'])
                log.error(result['stderr'])
                pytest.fail('Failed to approve cert request with NSSDB pwd')
