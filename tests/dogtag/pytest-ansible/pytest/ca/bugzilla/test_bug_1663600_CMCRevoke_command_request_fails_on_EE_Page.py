#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Bug - 1663600 CMCRevoke command request fails on EE Page
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Gaurav Swami <gswami@redhat.com>
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

import os
import sys
import time
import random
import pytest
import logging
import requests
import tempfile
from pki.testlib.common import utils

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir/')
        import constants


log = logging.getLogger()
profile = 'caUserCert'
csr_request_id = []
certificate_id = []
decimal = []
BASE_DIR = '/var/lib/pki'
ca_url = 'https://{}:{}'.format(constants.MASTER_HOSTNAME, constants.CA_HTTPS_PORT)
ca_instance = '{}'.format(constants.CA_INSTANCE_NAME)
Issuer_name = 'CN=CA Signing Certificate,OU=topology-02-CA,O=topology-02_Foobarmaster.org'
ca_cfg_path = BASE_DIR + '/' + ca_instance + '/' + 'ca/conf/CS.cfg'
add_param = "cmc.bypassClientAuth=true"
userop = utils.UserOperations(nssdb=constants.NSSDB)
logging.basicConfig(stream=sys.stdout,level=logging.INFO)

@pytest.fixture(autouse=True)
def setup_bz_1663600(ansible_module):
    """
        :Title: BZ 1663600: Test Setup
        :Description: This is test for setup creation to run CA Agent API tests
        :Steps:
            1. Create a valid Agent and CA Signing certificate pem files.
            2. Disable Nonces property.
            3. Change parameter cmc.bypassClientAuth value to True.
        :Expected Results:
           1. Nonces property is disabled.
           2. Valid Agent and CA Signing certificate pem files are created to be used in request module.
           3. cmc.bypassClientAuth parameter value set to true in CS.cfg.
    """
    ansible_module.lineinfile(path=ca_cfg_path, regexp="ca.enableNonces=true", line="ca.enableNonces=false")
    ansible_module.shell("openssl pkcs12 -in /opt/{}/ca_admin_cert.p12 "
                         "-out /tmp/auth_cert.pem -nodes -passin pass:{}".format(constants.CA_INSTANCE_NAME,
                                                                                 constants.CLIENT_DATABASE_PASSWORD))
    ansible_module.fetch(src="/tmp/auth_cert.pem", dest="/tmp/auth_cert.pem", flat="yes")
    ansible_module.lineinfile(path=ca_cfg_path,line=add_param, create='yes')
    ansible_module.fetch(src='/tmp/rootCA.pem', dest='/tmp/rootCA.pem', flat="yes")
    time.sleep(5)
    ansible_module.command('pki-server restart {}'.format(ca_instance))
    log.info("Restarted instance : {}".format(ca_instance))

    yield

    # Fix nonce
    ansible_module.lineinfile(path=ca_cfg_path, regexp="ca.enableNonces=false", line="ca.enableNonces=true")
    ansible_module.lineinfile(path=ca_cfg_path, regexp=add_param, state='absent')
    ansible_module.command('pki-server restart {}'.format(constants.CA_INSTANCE_NAME))

    # Delete certificate
    ansible_module.command('rm -rf /tmp/ca.crt /tmp/auth_cert.pem')
    for i in ['/tmp/rootCA.pem', '/tmp/auth_cert.pem']:
        os.remove(i)


def test_bug_1663600_cmc_revoke_failure(ansible_module):
    """
    :Title: CMCRevoke command request fails on EE Page
    :Description: CMCRevoke request sent to CA fails with 'Invalid Credential ' displayed on the EE page.
    :Requirement:  RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Generate the Certificate Request
        2. Approve the request
        3. Generate Certificate Revokation Request using 'CMCRevoke' command.
        4. Submit the request on EE Page
        5. Check Certificate status using CLI/Web-UI.

    :ExpectedResults:
        1. Certificate Request should raised succesfully.
        2. Should able to approve request.
        3. Should able to Revoke Certificate using EE Page.
        4. Certificate Status should be REVOKED.
    """
    tmp_file = tempfile.mktemp(suffix='_cert', prefix='blob_')
    for i in range(0, 3):
        user = 'testuser{}'.format(random.randint(1111, 99999))
        subject = 'UID={},CN=User {}'.format(user, user)
        cert_req = userop.create_certificate_request(ansible_module, subject=subject)
        review_req = userop.process_certificate_request(ansible_module, request_id=cert_req, action='approve')
        certificate_id.append(review_req)

    for i in certificate_id:
        decimal.append(int(i,16))

    cmc_revoke = ansible_module.command("CMCRevoke -d{} -n\"{}\" -i\"{}\" -s{} -m0 -t{} -p{}".format(constants.NSSDB,
                                                                                                          constants.CA_ADMIN_NICK,
                                                                                                          Issuer_name,
                                                                                                          decimal[1],
                                                                                                          constants.CLIENT_DIR_PASSWORD,
                                                                                                          constants.CLIENT_DIR_PASSWORD))
    for result in cmc_revoke.values():
        if result['rc'] == 0:
            assert "-----BEGIN CERTIFICATE REQUEST-----" in result['stdout']
            assert "-----END CERTIFICATE REQUEST-----" in result['stdout']
            assert "CMCRevoke: searching for certificate nickname:PKI CA Administrator for Example.Org" in result['stdout']
            log.info("CMCRevoke Command Run Succesfully {}".format(result['cmd']))
        else:
            log.error("Filed to run {}".format(result['cmd']))
            pytest.fail()

    # Converting Binary to ASCII
    path1 = '/root/CMCRevoke.out'
    path2 = '/root/CMCRevoke.txt'
    cmd = ansible_module.command("BtoA {} {}".format(path1,path2))
    cmd2 = ansible_module.fetch(src=path2,dest='/tmp/test.txt',flat=True)
    f = open('{}'.format('/tmp/test.txt'), 'r')
    lines = f.readlines()
    cert_str = '\t'.join([line.strip() for line in lines])

    cert_revoke_data = {
        'authenticator': 'CMCAuth',
        'cmcRequest': cert_str,
        'submit': 'submit'
    }

    response = requests.post(ca_url + "/ca/ee/ca/CMCRevReq",data=cert_revoke_data, verify='/tmp/rootCA.pem', cert="/tmp/auth_cert.pem")

    if response.status_code == 200:
        assert 'Certificate Revocation Has Been Completed' in response.content
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()

    # Verify Certificate Status with 'ca-cert-show'
    show_out = ansible_module.pki(cli='ca-cert-show',
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  port=constants.CA_HTTPS_PORT,
                                  protocol='https',
                                  certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                  extra_args=' {}'.format(certificate_id[1]))
    for result in show_out.values():
        if result['rc'] == 0:
            assert 'Serial Number:' in result['stdout']
            assert 'Issuer DN: ' in result['stdout']
            assert 'Subject DN: ' in result['stdout']
            assert 'Status: REVOKED' in result['stdout']
            log.info("Successfully Revoked Certificate With EE Page")
        else:
            pytest.fail("Failed to Run Command {}".format(result['cmd']))

