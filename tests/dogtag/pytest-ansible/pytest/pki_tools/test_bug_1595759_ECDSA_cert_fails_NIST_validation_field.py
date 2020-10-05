"""
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 #
 #   Description: Tests for BZ 1506826: org.mozilla.jss.pkix.primitive.
 #   AlgorithmIdentifier decode/encode process alters original data
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

import pytest
import sys

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
topology = constants.CA_INSTANCE_NAME.split("-")[1].strip()


@pytest.mark.skipif('topology != \'ecc\'')
def test_bug_1595759_ecdsa_certs_failed_nist_validation_field(ansible_module):
    """
    :Title: Test BZ: 1595759: ECDSA Certs fails NIST validation filed.BZ: 1547802, 1534772
    :Description: Test BZ: 1595759: ECDSA Certs fails NIST validation filed.BZ: 1547802, 1534772.
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
            1. Create CRMF request.
             - # PCRMFPopClient -d /root/nssdb -p SECret.123 -n 'CN=testuser101,UID=testuser101'
             -w 'AES/CBC/PKCS5Padding'  -q POP_SUCCESS -o testuser101.crmf -a ec -c nistp256 -v -y
             -t ture -b /root/transport.pem
            2. Create CMC config file.
                # cat /root/crmf_testuser101.cfg
                    dbdir=/root/nssdb
                    password=SECret.123
                    tokenname=internal
                    nickname=ECC_RootCA Admin
                    format=crmf
                    numRequests=1
                    input=/root/CMC/testuser101.crmf
                    output=/root/CMC/testuser101.bin

            2. Run CMCRequest /root/crmf_testuser1.cfg. This will create signed request in
               /root/crmf_testuser101.bin file.
            3. Create HttpClient file.
                # cat /root/http_client_submit_cmc.cfg
                # PKI server host name.
                host=pki1.example.com
                port=20443
                secure=true
                clientmode=true
                dbdir=/root/nssdb
                password=SECret.123
                tokenname=internal
                nickname=ECC_RootCA Admin
                servlet=/ca/ee/ca/profileSubmitCMCFull?profileId=caCMCECUserCert
                input=/root/testuser101.bin
                output=/root/testuser101_cmc-response.bin


            5. Run HttpClient /root/http_client_submit_cmc.cfg, it will submit the certificate
                request and approve it, and store the response in
                the /root/testuser101_cmc-response.bin
            6. Run CMCResponse -d /root/nssdb -i /root/testuser101_cmc-response.bin
            7. Using dumpasn1  /root/testuser101_cmc-response.bin > /root/testuser101.asn1.

    :Expectedresults:
                1. Make sure that ecdsaWithSHA256 block do not contain NULL.
                 232    8: . . . . . . . . . . . OBJECT IDENTIFIER
                         : . . . . . . . . . . . . ecdsaWithSHA256 (1 2 840 10045 4 3 2)
                         : . . . . . . . . . . . . (ANSI X9.62 ECDSA algorithm with SHA256)
                         : . . . . . . . . . . . }
    """
    name = 'testuser{}'.format(str(random.randint(111, 999)))
    subject = 'UID={},CN={}'.format(name, name)
    ecc_req_file = '/root/{}.req'.format(name)
    cmc_req_conf_file = '/root/crmf_{}.cfg'.format(name)
    cmc_req_out_file = '/root/cmc_req_out_{}.bin'.format(name)
    http_client_conf_file = '/root/http_client_{}.cfg'.format(name)
    cmc_response_bin_file = '/root/cmc_response_{}.bin'.format(name)
    user_cert = '/root/usercert_{}.pem'
    serial = None
    crmf_req = False
    req_genrated = False
    req_submitted = False
    files = []
    files.append(cmc_req_out_file)
    dumpasn_url = 'https://rpmfind.net/linux/fedora/linux/releases/27/Everything/x86_64/' \
                  'os/Packages/d/dumpasn1-20170309-1.fc27.x86_64.rpm'
    # Install dumpasn1 using ansible module.
    ansible_module.yum(name=dumpasn_url, state='present')
    asn_syntax_regex = r'.*ecdsaWithSHA.*[^}]+'

    crmf_cmd = 'CRMFPopClient -d {} -p {} -n "{}" -w "AES/CBC/PKCS5Padding" -q POP_SUCCESS ' \
               '-o {} -a ec -c nistp521 -v -y -t true'.format(constants.NSSDB,
                                                              constants.CLIENT_DIR_PASSWORD,
                                                              subject, ecc_req_file)
    crmf_cmd_out = ansible_module.command(crmf_cmd)
    for result in crmf_cmd_out.values():
        log.info("Running: {}".format(" ".join(result['cmd'])))
        if result['rc'] == 0:
            crmf_req = True
            assert 'Initializing security database:' in result['stdout']
            assert 'Parsing subject DN' in result['stdout']
            assert 'RDN: UID={}'.format(name) in result['stdout']
            assert 'RDN: CN={}'.format(name) in result['stdout']
            assert 'Generating key pair'.format(name) in result['stdout']
            assert 'Creating certificate request'.format(name) in result['stdout']
            assert 'Storing CRMF requrest into {}'.format(ecc_req_file) in result['stdout']
            log.info("Generated CRMF request for subject '{}' stored in {}.".format(subject,
                                                                                    ecc_req_file))
            files.append(ecc_req_file)
        else:
            log.error(result['stderr'])
            log.error(result)
            pytest.xfail("Failed to run '{}'".format(crmf_cmd))

    cmc_cfg_file = """
dbdir={}
password={}
tokenname=internal
nickname={}
format=crmf
numRequests=1
input={}
output={}
""".format(constants.NSSDB, constants.CLIENT_DIR_PASSWORD, constants.CA_ADMIN_NICK,
           ecc_req_file, cmc_req_out_file)

    ansible_module.copy(content=cmc_cfg_file, dest=cmc_req_conf_file)
    log.info("Created file {}".format(cmc_req_conf_file))
    files.append(cmc_req_conf_file)

    http_client_cfg_file = """
host={}
port={}
secure=true
clientmode=true
dbdir={}
password={}
tokenname=internal
nickname={}
servlet=/ca/ee/ca/profileSubmitCMCFull?profileId=caCMCECUserCert
input={}
output={}
""".format(constants.MASTER_HOSTNAME, constants.CA_HTTPS_PORT, constants.NSSDB,
           constants.CLIENT_DIR_PASSWORD, constants.CA_ADMIN_NICK, cmc_req_out_file,
           cmc_response_bin_file)

    ansible_module.copy(content=http_client_cfg_file, dest=http_client_conf_file)
    log.info("Created file {}".format(http_client_conf_file))
    files.append(http_client_conf_file)

    if crmf_req:
        CMCRequest = 'CMCRequest {}'.format(cmc_req_conf_file)
        cmc_out = ansible_module.command(CMCRequest)
        for res in cmc_out.values():
            log.info("Running: {}".format(" ".join(res['cmd'])))
            if res['rc'] == 0:
                assert 'The CMC enrollment request in binary format is ' \
                       'stored in {}'.format(cmc_req_out_file) in res['stdout']
                log.info("Created CMCRequest.")
                req_genrated = True
                http_client_cmd = 'HttpClient {}'.format(http_client_conf_file)
                http_client_out = ansible_module.command(http_client_cmd)
                for http_res in http_client_out.values():
                    log.info("Running: {}".format(" ".join(http_res['cmd'])))
                    if http_res['rc'] == 0:
                        assert 'The response in binary format is stored ' \
                               'in {}'.format(cmc_response_bin_file) in http_res['stdout']
                        req_submitted = True
                        log.info("Submitted CMC Request using HttpClient")
                    else:
                        log.error("Failed to submit the certificate request.")
                        log.error(http_res['stderr'])
                        pytest.xfail()

                cmc_response = 'CMCResponse -d {} -i {}'.format(constants.NSSDB,
                                                                cmc_response_bin_file)
                cmc_response_out = ansible_module.command(cmc_response)
                for result in cmc_response_out.values():
                    log.info("Running: {}".format(" ".join(result['cmd'])))
                    files.append(cmc_response_bin_file)
                    if result['rc'] == 0:
                        nos = re.findall("Serial Number: [\w].*", result['stdout'])
                        serial = nos[0].split(":")[1].strip()
                        log.info("Found user serial no: {}".format(serial))
                        cert_show = 'pki -p {} ca-cert-show {} ' \
                                    '--output {}'.format(constants.CA_HTTP_PORT, serial,
                                                         user_cert.format(serial))
                        export_cert = ansible_module.command(cert_show)
                        for r in export_cert.values():
                            if r['rc'] == 0:
                                assert 'Certificate "{}"'.format(serial.lower()) in r['stdout']
                                log.info("Exported user certificate to file: "
                                         "{}".format(user_cert.format(serial)))
                                files.append(user_cert.format(serial))
                                log.info("Converting certificate to bin.")
                                a_to_b = "AtoB {} {}.bin".format(user_cert.format(serial),
                                                                 user_cert.format(serial))
                                ansible_module.command(a_to_b)
                                files.append("{}.bin".format(user_cert.format(serial)))
                            else:
                                log.error("Failed to export user certificate.")
                                pytest.xfail("")
                        assert "SUCCESS" in result['stdout']
                    else:
                        log.error("Failed to Submit request.")
                        log.error(result['stderr'])
                        pytest.xfail("")
            else:
                log.error("Failed to create CMC Request.")
                log.error(res['stderr'])
                pytest.xfail()

    if req_genrated and req_submitted:
        dumpasn1 = ansible_module.command('dumpasn1 -a -d -v -l '
                                          '{}.bin'.format(user_cert.format(serial)))
        for res in dumpasn1.values():
            log.info("Running: {}".format(" ".join(res['cmd'])))
            if res['rc'] == 0 or res['rc'] == 1:
                asn_syntax = re.findall(asn_syntax_regex, res['stdout'])
                if asn_syntax:
                    for i in asn_syntax:
                        assert 'NULL' not in i
                else:
                    log.error("Failed to run: {}".format(res['cmd']))
                    log.error(res['stderr'])
                    pytest.xfail("")

    for f in files:
        log.info("Running: rm -rf {}".format(f))
        ansible_module.command('rm -rf {}'.format(f))
