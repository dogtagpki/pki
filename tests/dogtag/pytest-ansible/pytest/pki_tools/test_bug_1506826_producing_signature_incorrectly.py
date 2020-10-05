"""
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 #
 #   Description: Tests for BZ 1506826: org.mozilla.jss.pkix.cms.SignerInfo
 #   incorrectly producing signatures (especially for EC)
 # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 #
 #   Author: Amol Kahat <akahat@redhat.com>
 #
 # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 #
 #   Copyright (c) 2016 Red Hat, Inc. All rights reserved.
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
import random
import re
import sys

import pytest

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants


def test_bug_1506826_signature_producing_incorrectly(ansible_module):
    """
    :id: eab98724-9b67-4831-a0af-7c159ee3b42c

    :Title: Test BZ: 1506826: org.mozilla.jss.pkix.cms.SignerInfo incorrectly producing
            signatures (especially for EC)

    :Test: Test BZ: 1506826: org.mozilla.jss.pkix.cms.SignerInfo incorrectly producing
           signatures (especially for EC)

    :Description: This bug fixes the OID that goes into the signatureAlgorithm field as well as
                  passing the full signature algorithm to the Signature context to generate the
                  signature using the proper algorithm.

    :Requirement: RHCS-REQ Common Criteria - CMC Meet various CMC-related request and response requirements

    :CaseComponent: \-

    :Setup: Use the subsystems setup in ansible to run subsystem commands

    :Steps:
            1. Create Agent signed CMC request.
             - # PKCS10Client -d /opt/pki/certdb -p Secret123 -a ec -c nistp256 -o
             testuser1_ec.req -n "CN=testuser1"
             - Create CMC config file.
                # cat /root/crmf_testuser1.cfg
                    numRequests=1
                    host=pki1.example.com
                    port=20443
                    secure=true
                    input=/root/testuser1.req
                    output=/root/cmc_req_testuser1.req
                    tokenname=internal
                    dbdir=/opt/pki/certdb
                    clientmode=true
                    format=pkcs10
                    password=Secret123
                    nickname=PKI CA Administrator for Example.Org
                    servlet=/ca/ee/ca/profileSubmitCMCFull
            2. Run CMCRequest /root/crmf_testuser1.cfg. This will create signed request in
               /root/crmf_req_testuser1.req file.
            3. Using dumpasn1 get the structure of the request.

    :Expectedresults:
                1. Make sure that signature block will properly produce the signature.
                 232    8: . . . . . . . . . . . OBJECT IDENTIFIER
                         : . . . . . . . . . . . . ecdsaWithSHA256 (1 2 840 10045 4 3 2)
                         : . . . . . . . . . . . . (ANSI X9.62 ECDSA algorithm with SHA256)
                    <05 00>
                 242    0: . . . . . . . . . . . NULL
                         : . . . . . . . . . . . }
                    <03 47>
                 244   71: . . . . . . . . . . BIT STRING, encapsulates {
                    <30 44>
                 247   68: . . . . . . . . . . . SEQUENCE {
                    <02 20>
                 249   32: . . . . . . . . . . . . INTEGER
                         : . . . . . . . . . . . . . 4B 99 94 7F A0 EC A9 FD    K.......
                         : . . . . . . . . . . . . . 8F A0 F1 2F DB 74 08 6A    .../.t.j
                         : . . . . . . . . . . . . . 17 2E F1 C0 1D E6 1D 29    .......)
                         : . . . . . . . . . . . . . F8 E1 A6 EE 43 53 52 7B
                    <02 20>
                 283   32: . . . . . . . . . . . . INTEGER
                         : . . . . . . . . . . . . . 4A E8 89 7E E5 B4 54 41    J..~..TA
                         : . . . . . . . . . . . . . F5 E0 45 5C A1 9A 42 0A    ..E\..B.
                         : . . . . . . . . . . . . . 17 49 86 28 DD 8F 02 E5    .I.(....
                         : . . . . . . . . . . . . . 2D B2 78 9A 6F B5 5E 7C
                         : . . . . . . . . . . . . }
                         : . . . . . . . . . . . }
    """
    name = 'testuser{}'.format(str(random.randint(111, 999)))
    subject = 'UID={},CN={}'.format(name, name)
    ecc_req_file = '/root/{}.req'.format(name)
    cmc_req_file = '/root/cmc_req_{}.req'.format(name)
    crmf_conf_file = '/root/crmf_{}.cfg'.format(name)
    pkcs10_req = False
    req_genrated = False
    dumpasn_url = 'https://rpmfind.net/linux/fedora/linux/releases/27/Everything/x86_64/' \
                  'os/Packages/d/dumpasn1-20170309-1.fc27.x86_64.rpm'

    asn_syntax_regex = r'BIT\sSTRING,\sencapsulates.*\sSEQUENCE\s\{(?<=\{)\s*[^{]*?(?=[\},])'
    pkcs10_cmd = 'PKCS10Client -d {} -p {} -a ec -c nistp256 -o {} -n {}'.format(
        constants.NSSDB, constants.CLIENT_DIR_PASSWORD, ecc_req_file, subject)
    pkcs10_out = ansible_module.command(pkcs10_cmd)
    for _, result in pkcs10_out.items():
        if result['rc'] == 0:
            pkcs10_req = True
            assert '-----BEGIN CERTIFICATE REQUEST-----' in result['stdout']
            assert '-----END CERTIFICATE REQUEST-----' in result['stdout']
            assert 'PKCS10Client: PKCS#10 request key id written into {}'.format(ecc_req_file) in \
                   result['stdout']

        else:
            pytest.xfail("Failed to run '{}'".format(pkcs10_cmd))

    write_file = """
numRequests=1
host=pki1.example.com
port={}
secure=true
input={}
output={}
tokenname=internal
dbdir={}
clientmode=true
format=pkcs10
password={}
nickname={}
servlet=/ca/ee/ca/profileSubmitCMCFull
""".format(constants.CA_HTTPS_PORT, ecc_req_file, cmc_req_file, constants.NSSDB,
           constants.CLIENT_DIR_PASSWORD, constants.CA_ADMIN_NICK)

    ansible_module.copy(content=write_file, dest=crmf_conf_file)

    # Install dumpasn1 using ansible module.
    ansible_module.yum(name=dumpasn_url, state='present')

    if pkcs10_req:
        CMCRequest = 'CMCRequest {}'.format(crmf_conf_file)
        cmc_out = ansible_module.command(CMCRequest)
        for _, res in cmc_out.items():
            if res['rc'] == 0:
                assert 'The CMC enrollment request in binary format is ' \
                       'stored in {}'.format(cmc_req_file) in res['stdout']
                req_genrated = True

    if req_genrated:
        dumpasn1 = ansible_module.command('dumpasn1 -a -d -v -l {}'.format(cmc_req_file))
        for _, res in dumpasn1.items():
            if res['rc'] == 0 or res['rc'] == 1:
                asn_syntax = re.findall(asn_syntax_regex, res['stdout'], re.S)
                if asn_syntax:
                    assert 'BIT STRING, encapsulates {' in asn_syntax[0]
                    assert 'SEQUENCE {' in asn_syntax[0]
                    assert 'INTEGER' in asn_syntax[0]

    for f in [cmc_req_file, ecc_req_file, crmf_conf_file]:
        ansible_module.command('rm -rf {}'.format(f))
