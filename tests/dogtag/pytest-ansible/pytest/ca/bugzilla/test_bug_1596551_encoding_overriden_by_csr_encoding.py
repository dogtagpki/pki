#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Bug 1596551 - X500Name.directoryStringEncodingOrder overridden by CSR encoding
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
import random
import sys

import pytest

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

import tempfile

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
topology = int(constants.CA_INSTANCE_NAME.split("-")[-2])


# userop = utils.UserOperations(nssdb=constants.NSSDB)


def test_bug_1596551_encoding_overriden_by_csr_encoding(ansible_module):
    """
    :Title: Bug 1596551 - X500Name.directoryStringEncodingOrder overridden by CSR encoding

    :Description: Bug 1596551 - X500Name.directoryStringEncodingOrder overridden by CSR encoding

    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment

    :Setup:
        1. Setup DS instance
        2. Setup CA instance

    :Steps:
        1. Setup DS instance
        2. Setup CA (by default, it should use UTF8String)
        3. generate a request (e.g. pkcs#10) with subject dn (e.g. cn=testuser4)
           verify that the request subjectdn is indeed encoded with UTF8String
           PKCS10Client -d /tmp/nssdb/ -p SECret.123 -n cn=testUser4 -o testUser4pkcs10cert.req
        4. Use the config file attached to run CMCRequest
           CMCRequest cmc-selfsigned.cfg
        5. Use the HttpClient config to run HttpClient
           HttpClient agent_http.cfg
           verify that the cert subjectdn is indeed encoded with UTF8String using dumpasn1
           Before running dumpasn1 make sure you convert the exported cert to bin format using AtoB tool
        6. Stop CA. edit CA's CS.cfg and add:
           X500Name.directoryStringEncodingOrder=PrintableString,UTF8String,T61String,BMPString,UniversalString
           Restart CA
        7. Perform the above test again, expect the resulting cert is still encoded with UTF8String
        8. stop CA
           edit the profile and add the following :
           policyset.cmcUserCertSet.1.default.params.useSysEncoding=true
           to caFullCMCUserCert.cfg
           restart CA

    :Expectedresults:
        1. DS instance is setup successfully
        2. CA instance is setup successfully
        3. CSR generation using PKCS10Client should succeed and the CSR should be stored in testUser4pkcs10cert.req
        4. CMCRequest is run successfully, csr.self.req should be generated
        5. HttpClient is run successfully and the certificate should be generated successfully
        6. CA restarts successfully after editing CA's CS.cfg
        7. The above test should succeed again with Step 6 configuration
        8. caFullCMCUserCert.cfg is edited and CA starts successfully
           After making changes to the profile the subjectDN encoding is now PrintableString

    :Automated: No
    """


@pytest.mark.skipif("topology != 2")
def test_pki_bug_1629048_x500_string_encoding_order_changed_by_csr_encoding(ansible_module):
    """
    :Title: Test pki bug 1629048 String encoding order changed by CSR encoding
    :Description: Test pki bug 1629048 String encoding order changed by CSR encoding
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Create CRMFPopClient request
        2. Create CMCRequest using following file
            $ cat cmc_request.cfg
            numRequests=1
            format=crmf
            dbdir=/root/nssdb
            nickname=PKI CA Administrator for Example.Org
            password=SECret.123
            tokenname=internal
            input=/root/cmc/testuser2_crmf.req
            output=/root/cmc/testuser2_req.out

        3. Create HttpClient request using following file.
            $ cat http_client.cfg
            host=pki1.example.com
            port=20443
            secure=true
            input=/root/cmc/testuser2_req.out
            output=/root/cmc/testuser2_client.resp
            tokenname=internal
            dbdir=/root/nssdb
            clientmode=true
            password=SECret.123
            nickname=PKI CA Administrator for Example.Org
            servlet=/ca/ee/ca/profileSubmitCMCFull
        4. Check for certificate got enrolled or not.
    :ExpectedResults:
        1. Certificate should get enrolled.
    """
    crmf_request = False
    req_genrated = False

    # RSA Certificate request file contents.
    tempdb = constants.NSSDB
    name = 'testuser{}'.format(str(random.randint(111, 999)))
    subject = 'UID={},CN={}'.format(name, name)
    rsa_crmf_cert_req_file = '/tmp/{}.req'.format(name)

    # CMCRequest file contents
    cmc_req_out_file = '/tmp/cmc_req_{}.req'.format(name)
    cmc_conf_file = '/tmp/crmf_{}.cfg'.format(name)
    cmc_req_file_content = """
numRequests=1
dbdir={}
format=crmf
nickname={}
password={}
tokenname=internal
input={}
output={}
""".format(tempdb, constants.CA_ADMIN_NICK, constants.CA_PASSWORD,
           rsa_crmf_cert_req_file, cmc_req_out_file)

    # HttpClient file contents
    http_client_conf_file = '/tmp/http_client_{}.cfg'.format(name)
    http_request_out_file = '/tmp/http_response_{}.out'.format(name)
    http_client_file_contents = """
numRequests=1
host=pki1.example.com
port={}
secure=true
input={}
output={}
tokenname=internal
dbdir={}
clientmode=true
format=crmf
password={}
nickname={}
servlet=/ca/ee/ca/profileSubmitCMCFull
        """.format(constants.CA_HTTPS_PORT, cmc_req_out_file, http_request_out_file, tempdb,
                   constants.CLIENT_DIR_PASSWORD, constants.CA_ADMIN_NICK)

    crmf_pop_client_cmd = 'CRMFPopClient -d {} -p {} -a rsa -l 2048 -o {} -n "{}" ' \
                          '-h internal -y true'.format(tempdb, constants.CLIENT_DIR_PASSWORD,
                                                       rsa_crmf_cert_req_file, subject)
    crmf_out = ansible_module.command(crmf_pop_client_cmd)
    for result in crmf_out.values():
        if result['rc'] == 0:
            log.info("Generated Certificate request in: {}".format(rsa_crmf_cert_req_file))
            crmf_request = True
            assert "Storing CRMF request into {}".format(rsa_crmf_cert_req_file) in result['stdout']
            out = ansible_module.stat(path=rsa_crmf_cert_req_file)
            for res in out.values():
                if res['stat']['exists']:
                    cat_out = ansible_module.command('cat {}'.format(rsa_crmf_cert_req_file))
                    for r in cat_out.values():
                        if r['rc'] == 0:
                            assert '-----BEGIN CERTIFICATE REQUEST-----' in r['stdout']
                            assert '-----END CERTIFICATE REQUEST-----' in r['stdout']
                        else:
                            pytest.fail("Failed to print the content in the file.")
                else:
                    pytest.fail("File does not exists.")
        else:
            pytest.fail("Failed to run '{}'".format(crmf_pop_client_cmd))

    ansible_module.copy(content=cmc_req_file_content, dest=cmc_conf_file)
    log.info("Created CMCRequest conf file: {}".format(cmc_conf_file))
    ansible_module.copy(content=http_client_file_contents, dest=http_client_conf_file)
    log.info("Created HttpClient conf file: {}".format(http_client_conf_file))

    # ansible_module.yum(name=dumpasn_url, state='present')

    if crmf_request:
        CMCRequest = 'CMCRequest {}'.format(cmc_conf_file)
        log.info("Running: {}".format(CMCRequest))
        cmc_out = ansible_module.command(CMCRequest)
        for res in cmc_out.values():
            if res['rc'] == 0:
                assert 'The CMC enrollment request in binary format is ' \
                       'stored in {}'.format(cmc_req_out_file) in res['stdout']
                req_genrated = True
            else:
                pytest.fail(res)

        if req_genrated:
            http_client_cmd = 'HttpClient {}'.format(http_client_conf_file)
            log.info("Running: {}".format(http_client_cmd))
            http_cmd_out = ansible_module.command(http_client_cmd)
            for res in http_cmd_out.values():
                if res['rc'] == 0:
                    assert "The response in binary format is stored in {}".format(http_request_out_file)
                    cert_find = 'pki -d {} -p {} ca-cert-find --size 1000'.format(constants.NSSDB,constants.CA_HTTPS_PORT)
                    check_cert = ansible_module.command(cert_find)
                    log.info("Running: {}".format(cert_find))
                    for certs in check_cert.values():
                        if certs['rc'] == 0:
                            assert "Subject DN: {}".format(subject) in certs['stdout']
                            log.info("Found: Subject DN: {}".format(subject))
                        else:
                            pytest.fail("Failed to search the certificates")
                else:
                    pytest.fail(res)

    for i in [cmc_conf_file, cmc_req_out_file,
              http_client_conf_file, http_request_out_file, rsa_crmf_cert_req_file,
              rsa_crmf_cert_req_file + ".keyId"]:
        ansible_module.command("rm -rf {}".format(i))
    # TODO: Fix this after resolving: 1744095
    # if req_genrated:
    #     dumpasn1 = ansible_module.command('dumpasn1 -a -d -v -l {}'.format(cmc_req_file))
    #     for _, res in dumpasn1.items():
    #         if res['rc'] == 0 or res['rc'] == 1:
    #             asn_syntax = re.findall(asn_syntax_regex, res['stdout'], re.S)
    #             if asn_syntax:
    #                 assert 'BIT STRING, encapsulates {' in asn_syntax[0]
    #                 assert 'SEQUENCE {' in asn_syntax[0]
    #                 assert 'INTEGER' in asn_syntax[0]

    # for f in [cmc_req_file, ecc_req_file, crmf_conf_file]:
    #     ansible_module.command('rm -rf {}'.format(f))
