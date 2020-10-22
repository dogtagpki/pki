#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI SubCA Sanity Tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following SubCA commands needs to be tested:
#   pki client-cert-request --type crmf
#   pki ca-cert-request-approve
#   pki kra-key-retrieve
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
import logging
import os
import re
import sys
import random
import pytest
from pki.testlib.common.certlib import CertSetup

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)


@pytest.mark.bugzilla('1854959')
@pytest.mark.setup
def test_setup(ansible_module):
    """
    :id: 88a1574b-8509-48bb-bfb5-61920295ebae
    :Title: Test create nssdb and import admin certs
    :Description: Test create nssdb and import admin certs
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement: RHCS-REQ Subordinate Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d <nssdb> -c SECret.123 client-init
        2. pki -d <nssdb> -c SECret.123 -p <subca_secure_port> client-cert-import --ca-server
        3. pki -d <nssdb> -c SECret.123 -p <subca_secure_port> client-cert-import --pkcs12 <subca_admin_path>
           --pkcs12-password <Password>
        4. pki -d <nssdb> -c SECret.123 -p <subca_secure_port> client-cert-import --pkcs12 <subkra_admin_path>
           --pkcs12-password <Password>
    :ExpectedResults:
         Verify whether admin certs are imported into nssdb
    :Automated: yes
    """
    cert_setup = CertSetup(nssdb=constants.NSSDB,
                           db_pass=constants.CLIENT_DATABASE_PASSWORD,
                           host='{}'.format(constants.MASTER_HOSTNAME),
                           port=constants.SUBCA_HTTPS_PORT,
                           protocol=constants.PROTOCOL_SECURE,
                           nick="'{}'".format(constants.SUBCA_ADMIN_NICK))
    cert_setup.create_certdb(ansible_module)
    cert_import = 'pki -d {} -c {} -p {} client-cert-import --ca-server'.format(constants.NSSDB,
                                                                        constants.CLIENT_DATABASE_PASSWORD,
                                                                        constants.SUBCA_HTTPS_PORT)
    ansible_module.expect(
        command=cert_import,
        responses={"Trust this certificate (y/N)?": 'y'})
    import_subca_admin_p12 = ansible_module.pki(
        cli='client-cert-import',
        nssdb=constants.NSSDB,
        dbpassword=constants.CLIENT_DATABASE_PASSWORD,
        port=constants.SUBCA_HTTPS_PORT,
        protocol='https',
        extra_args='--pkcs12 /opt/{}/ca_admin_cert.p12 '
                   '--pkcs12-password {} '.format(constants.SUBCA_INSTANCE_NAME, constants.CLIENT_PKCS12_PASSWORD))
    for result in import_subca_admin_p12.values():
        assert "Imported certificate" in result['stdout']
        log.info('Imported SubCA Admin Cert')
    import_kra_admin_p12 = ansible_module.pki(
        cli='client-cert-import',
        nssdb=constants.NSSDB,
        dbpassword=constants.CLIENT_DATABASE_PASSWORD,
        port=constants.SUBCA_HTTPS_PORT,
        protocol='https',
        extra_args='--pkcs12 {}/kra_admin_cert.p12 '
                   '--pkcs12-password {} '.format(constants.KRA_CLIENT_DIR, constants.CLIENT_PKCS12_PASSWORD))
    for result in import_kra_admin_p12.values():
        assert "Imported certificate" in result['stdout']
        log.info('Imported KRA Admin Cert')


@pytest.mark.bugzilla('1854959')
def test_pki_subca_sanity(ansible_module):
    """
    :id: 0869bbc7-471f-4096-bd9a-80c47e3c49bc
    :Title: Test pki subca sanity tests
    :Description: Test pki subca sanity tests
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement: RHCS-REQ Subordinate Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d <nssdb> -c SECret.123 -p <subca_secure_port> client-cert-request 'uid=test' --type crmf
        2. pki -d <nssdb> -c SECret.123 -p <subca_secure_port> -n "nickname" ca-cert-request-approve <r_id>
        3. pki -d <nssdb> -c SECret.123 -p <kra_secure_port> -n 'kra_nickname' kra-key-retrieve
    :ExpectedResults:
         Verify whether cert request, approval and kra archival and retrieval works fine
    :Automated: yes
    """
    user = "foouser{}".format(random.randint(1111, 99999))
    subject = 'UID={},CN={}'.format(user, user)
    cert_req = ansible_module.pki(cli='client-cert-request',
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DIR_PASSWORD,
                                      port=constants.SUBCA_HTTPS_PORT,
                                      protocol='https',
                                      certnick='"{}"'.format(constants.SUBCA_ADMIN_NICK),
                                      extra_args='"{}" --type crmf'.format(subject))
    for result in cert_req.values():
        if result['rc'] == 0:
            request_id_raw = re.findall('Request ID: [\w].*', result['stdout'])
            request_id = request_id_raw[0].split(":")[1].strip()
            assert 'Request ID: {}'.format(request_id) in result['stdout']
            assert 'Type: enrollment' in result['stdout']
            assert 'Request Status: pending' in result['stdout']
            assert 'Operation Result: success' in result['stdout']
            log.info("Successfully run '{}'".format(cert_req))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail("Failed to run '{}'".format(cert_req))

    req_approve = 'pki -d {} -c {} -n "{}" -p {} ca-cert-request-approve {}'.format(constants.NSSDB,
                                                                                    constants.CLIENT_DATABASE_PASSWORD,
                                                                                    constants.SUBCA_ADMIN_NICK,
                                                                                    constants.SUBCA_HTTPS_PORT,
                                                                                    request_id)
    log.info("Running: {}".format(req_approve))
    cmd_out = ansible_module.expect(
        command=req_approve,
        responses={"Are you sure (Y/N)?": 'y'})
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Approved certificate request {}'.format(request_id) in result['stdout']
            assert 'Request ID: {}'.format(request_id) in result['stdout']
            assert 'Type: enrollment' in result['stdout']
            assert 'Request Status: complete' in result['stdout']
            assert 'Operation Result: success' in result['stdout']
            log.info('Successfully Ran: {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    key_find = ansible_module.pki(cli='kra-key-find',
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DIR_PASSWORD,
                                      port=constants.KRA_HTTPS_PORT,
                                      protocol='https',
                                      certnick='"{}"'.format(constants.KRA_ADMIN_NICK))
    for result in key_find.values():
        if result['rc'] == 0:
            key_id_raw = re.findall('Key ID: [\w].*', result['stdout'])
            key_id = key_id_raw[0].split(":")[1].strip()
            assert '  Key ID: {}'.format(key_id) in result['stdout']
            assert '  Size: 2048' in result['stdout']
            assert '  Algorithm: 1.2.840.113549.1.1.1' in result['stdout']
            assert '  Owner: {}'.format(subject) in result['stdout']
            log.info("Successfully run '{}'".format(key_find))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail("Failed to run '{}'".format(key_find))

    key_retrieve = ansible_module.pki(cli='kra-key-retrieve',
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DIR_PASSWORD,
                                      port=constants.KRA_HTTPS_PORT,
                                      protocol='https',
                                      certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                      extra_args='--keyID {}'.format(key_id))
    for result in key_retrieve.values():
        if result['rc'] == 0:
            assert '<algorithm>1.2.840.113549.1.1.1</algorithm>' in result['stdout']
            assert '<wrapAlgorithm>AES KeyWrap/Padding</wrapAlgorithm>' in result['stdout']
            assert '<type>asymmetricKey</type>' in result['stdout']
            log.info("Successfully run '{}'".format(key_retrieve))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail("Failed to run '{}'".format(key_retrieve))
