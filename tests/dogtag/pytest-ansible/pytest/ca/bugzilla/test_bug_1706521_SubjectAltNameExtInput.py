#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Bug 1465103 - CA - SubjectAltNameExtInput does not
#                display text fields to the enrollment page
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Chandan Pinjani<cpinjani@redhat.com>
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
import time
import sys
import logging
import pytest
import re
import random
import requests

from pki.testlib.common.utils import ProfileOperations

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

TOPOLOGY = constants.CA_INSTANCE_NAME.split("-")[-2]
if TOPOLOGY == '01':
    instance = "pki-tomcat"
else:
    instance = constants.CA_INSTANCE_NAME

user_num = random.randint(111111, 999999)
profile = "caServerCert{}".format(user_num)
profile_param = "/tmp/{}.txt".format(profile)
BASE_DIR = '/var/lib/pki/'
ca_cfg_path = BASE_DIR + '/' + instance + '/' + 'ca/conf/CS.cfg'
ca_url = 'https://{}:{}'.format(constants.MASTER_HOSTNAME, constants.CA_HTTPS_PORT)
profop = ProfileOperations(nssdb=constants.NSSDB)
valid_agent_user = 'CA_AgentV'
valid_agent_cert = '/tmp/{}.pem'.format(valid_agent_user)
ca_cert = BASE_DIR + '/' + instance + "/alias/ca.crt"

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)


def restart_instance(ansible_module, instance=instance):
    command = 'systemctl restart pki-tomcatd@{}'.format(instance)
    time.sleep(10)
    out = ansible_module.command(command)
    for res in out.values():
        assert res['rc'] == 0


@pytest.fixture(autouse=True)
def module_setup(ansible_module):
    """
    :Title: CA Agent tests: Test Setup
    :Description: This is test for setup creation to run CA Agent API tests
    :Steps:
        1. Create a valid Agent and CA Signing certificate pem files
        2. Disable Nonces property
    :Expected Results:
       1. Nonces property is disabled
       2. Valid Agent and CA Signing certificate pem files are created to be used in request module
    """
    ansible_module.lineinfile(path=ca_cfg_path, regexp="ca.enableNonces=true", line="ca.enableNonces=false")
    restart_instance(ansible_module)
    log.info("Restarted instance : {}".format(instance))

    ansible_module.shell('pki -d {} -c {} pkcs12-cert-import {} --pkcs12-file /tmp/{}.p12 --pkcs12-password {}'.format(constants.NSSDB, constants.CLIENT_DATABASE_PASSWORD, valid_agent_user, valid_agent_user, constants.CLIENT_DATABASE_PASSWORD))
    ansible_module.shell("openssl pkcs12 -in /tmp/{}.p12 -out {} -nodes -passin pass:{}".format(valid_agent_user, valid_agent_cert, constants.CLIENT_DATABASE_PASSWORD))
    ansible_module.fetch(src=valid_agent_cert, dest=valid_agent_cert, flat="yes")
    ansible_module.fetch(src=ca_cert, dest='/tmp/', flat="yes")
    yield
    ansible_module.lineinfile(path=ca_cfg_path, regexp="ca.enableNonces=false", line="ca.enableNonces=true")
    ansible_module.command('rm -rf {} {}'.format(valid_agent_cert, ca_cert))
    restart_instance(ansible_module)

def test_bug_1706521(ansible_module):
    """
    :id: 9130bcc4-6203-4d78-b9ce-a334bb05ec6a
    :Title: Bug 1706521 - SubjectAltNameExtInput does not display text fields to the enrollment page
    :Description: Bug 1706521 - SubjectAltNameExtInput does not display text fields to the enrollment page
    :Requirement: RHCS-REQ Certificate Authority Profiles
    :CaseComponent: \-
    :Setup:
        1. Use the subsystems setup in ansible to run subsystem commands
        2. Use the CA setup certificate files to run CA Agent APIs
    :Steps:
        1. Create a CA profile with relevant subjectAltNameExtInputImpl info:
        desc=This certificate profile is for enrolling server certificates caServerCert1706521
        enable=true
        input.i1.class_id=certReqInputImpl
        input.i2.class_id=submitterInfoInputImpl
        input.i3.class_id=subjectAltNameExtInputImpl
        input.list=i1,i2,i3
        name=caServerCert1706521
        profileId=caServerCert1706521
        ...
        policyset.serverCertSet.9.default.class_id=subjectAltNameExtDefaultImpl
        policyset.serverCertSet.9.default.name=Subject Alternative Name Extension Default
        policyset.serverCertSet.9.default.params.subjAltExtGNEnable_0=true
        policyset.serverCertSet.9.default.params.subjAltExtGNEnable_1=true
        policyset.serverCertSet.9.default.params.subjAltExtPattern_0=$request.req_san_pattern_0$
        policyset.serverCertSet.9.default.params.subjAltExtPattern_1=$request.req_san_pattern_1$
        policyset.serverCertSet.9.default.params.subjAltExtType_0=DNSName
        policyset.serverCertSet.9.default.params.subjAltExtType_1=DNSName
        policyset.serverCertSet.9.default.params.subjAltNameExtCritical=false
        policyset.serverCertSet.9.default.params.subjAltNameNumGNs=2
        policyset.serverCertSet.list=1,2,3,4,5,6,7,8,9
        policyset.serverCertSet.9.constraint.class_id=noConstraintImpl
        policyset.serverCertSet.9.constraint.name=No Constraint
        2. Entry in CS.cfg matching with subjAltNameNumGNs: ca.SAN.entryNum=2
        3. Go to the CA EE Page and click on the profile, the page is displaying Subject Alternative Name Extension Information with text boxes
        4. Submit the certificate request and approve
        5. Check the certificate with relevant Subject Alternative Name info
    :ExpectedResults:
        1. Profile should be generated successfully
        2. Certificate Request should raised successfully
        3. Certificate Request should be approved successfully
        4. Certificate details should displayed successfully with Subject Alternative Name info
        5. DNSName count must match with subjAltNameNumGNs value
    """
    profile_add = False
    add_params = ['input.i3.class_id=subjectAltNameExtInputImpl',
                  'policyset.serverCertSet.9.default.class_id=subjectAltNameExtDefaultImpl',
                  'policyset.serverCertSet.9.default.name=Subject Alternative Name Extension Default',
                  'policyset.serverCertSet.9.default.params.subjAltExtGNEnable_0=true',
                  'policyset.serverCertSet.9.default.params.subjAltExtGNEnable_1=true',
                  'policyset.serverCertSet.9.default.params.subjAltExtGNEnable_2=true',
                  'policyset.serverCertSet.9.default.params.subjAltExtGNEnable_3=true',
                  'policyset.serverCertSet.9.default.params.subjAltExtPattern_0=$request.req_san_pattern_0$',
                  'policyset.serverCertSet.9.default.params.subjAltExtPattern_1=$request.req_san_pattern_1$',
                  'policyset.serverCertSet.9.default.params.subjAltExtPattern_2=$request.req_san_pattern_2$',
                  'policyset.serverCertSet.9.default.params.subjAltExtPattern_3=$request.req_san_pattern_3$',
                  'policyset.serverCertSet.9.default.params.subjAltExtType_0=DNSName',
                  'policyset.serverCertSet.9.default.params.subjAltExtType_1=DNSName',
                  'policyset.serverCertSet.9.default.params.subjAltExtType_2=DNSName',
                  'policyset.serverCertSet.9.default.params.subjAltExtType_3=DNSName',
                  'policyset.serverCertSet.9.default.params.subjAltNameExtCritical=false',
                  'policyset.serverCertSet.9.default.params.subjAltNameNumGNs=4',
                  'policyset.serverCertSet.9.constraint.class_id=noConstraintImpl',
                  'policyset.serverCertSet.9.constraint.name=No Constraint']

    cmd = ansible_module.shell('pki -d {} -c {} -p {} -n "{}" ca-profile-show caServerCert --raw --output {}'.format(constants.NSSDB,
                                                                                    constants.CLIENT_DATABASE_PASSWORD,
                                                                                    constants.CA_HTTPS_PORT,
                                                                                    constants.CA_ADMIN_NICK, profile_param))
    for result in cmd.values():
        if result['rc'] == 0:
            ansible_module.lineinfile(path=ca_cfg_path, line="ca.SAN.entryNum=4")
            ansible_module.lineinfile(path=profile_param, regexp="policyset.serverCertSet.list=1,2,3,4,5,6,7,8,12",
                                      line="policyset.serverCertSet.list=1,2,3,4,5,6,7,8,9")
            ansible_module.lineinfile(path=profile_param, regexp="input.list=i1,i2", line="input.list=i1,i2,i3")
            ansible_module.lineinfile(path=profile_param, regexp="profileId=caServerCert", line="profileId={}".format(profile))
            ansible_module.lineinfile(path=profile_param, regexp="name=Manual Server Certificate Enrollment",
                                      line='name={}'.format(profile))
            for i in add_params:
                ansible_module.lineinfile(path=profile_param, line=i)
            restart_instance(ansible_module)
            time.sleep(20)
        else:
            log.error("Failed to create {} profile param file".format(profile_param))
            log.error(result['stderr'])
            pytest.fail()

    # Add new created profile
    cmd = ansible_module.shell('pki -d {} -c {} -p {} -n "{}" ca-profile-add --raw {}'.format(constants.NSSDB,
                                                                                    constants.CLIENT_DATABASE_PASSWORD,
                                                                                    constants.CA_HTTPS_PORT,
                                                                                    constants.CA_ADMIN_NICK, profile_param))
    for result in cmd.values():
        if result['rc'] == 0:
            profile_add = True
            assert "Added profile {}".format(profile) in result['stdout']
            log.info("Successfully ran: '{}'".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            log.error("Failed to run: '{}'".format(result['cmd']))
            pytest.fail()

    # Disable new added profile
    profop.disable_profile(ansible_module, profile)

    # Enable new added profile
    enabled = profop.enable_profile(ansible_module, profile)
    assert enabled

    if profile_add:
        cmd = ansible_module.shell('pki -d {} -c {} -p {} -n "{}" ca-profile-show --raw {}'.format(constants.NSSDB,
                                                                             constants.CLIENT_DATABASE_PASSWORD,
                                                                             constants.CA_HTTPS_PORT,
                                                                             constants.CA_ADMIN_NICK, profile))
        for res in cmd.values():
            if res['rc'] == 0:
                assert 'policyset.serverCertSet.9.default.params.subjAltNameNumGNs=4' in res['stdout']
                assert 'policyset.serverCertSet.9.default.class_id=subjectAltNameExtDefaultImpl' in res['stdout']
                log.info("Successfully ran: '{}'".format(res['cmd']))
            else:
                log.error(res['stderr'])
                pytest.fail("Failed to show {} profile".format(profile))

    user_id = 'user{}'.format(user_num)
    pop_cert = "/tmp/{}".format(user_id)
    pop_out = ansible_module.shell('CRMFPopClient -d {} -p {} -a rsa -n "cn={}" -o {}'.format(constants.NSSDB, constants.CLIENT_DATABASE_PASSWORD, user_id, pop_cert))
    for result in pop_out.values():
        if result['rc'] == 0:
            ansible_module.fetch(src=pop_cert, dest=pop_cert, flat="yes")
            encoded_cert = open(pop_cert, "r").read()
            log.info("Successfully ran: '{}'".format(result['cmd']))
        else:
            log.error(result['stderr'])
            pytest.fail("Failed to run: {}".format("".join(result['cmd'])))

    req_data = {
        'requestor_name': user_id,
        'requestor_phone': user_num,
        'requestor_email': '{}@example.com'.format(user_id),
        'profileId': profile,
        'cert_request_type': 'crmf',
        'cert_request': '{}'.format(encoded_cert),
        'req_san_type_0': 'DNS1',
        'req_san_pattern_0': 'www.example1.org',
        'req_san_type_1': 'DNS2',
        'req_san_pattern_1': 'www.example2.com',
        'req_san_type_2': 'DNS3',
        'req_san_pattern_2': 'www.example3.edu',
        'req_san_type_3': 'DNS4',
        'req_san_pattern_3': 'www.example4.gov',
        'renewal': 'false',
        'xmlOutput': 'false'
    }
    response = requests.post(ca_url + "/ca/ee/ca/profileSubmit", data=req_data, verify='/tmp/ca.crt', cert=valid_agent_cert)
    if response.status_code == 200:
        request = re.findall('requestList.requestId="[\w]*"', response.content)
        request_id = request[0].split("=")[1].strip().replace("\"", "")
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()

    # Approve Above Request with request number
    cmd = 'pki -d {} -c {} -p {} -n "{}" ca-cert-request-approve {}'.format(constants.NSSDB,
                                                                                    constants.CLIENT_DATABASE_PASSWORD,
                                                                                    constants.CA_HTTPS_PORT,
                                                                                    constants.CA_ADMIN_NICK, request_id)
    cert_res = ansible_module.expect(command=cmd, responses={"Are you sure (y/N)?": "y"})
    for result in cert_res.values():
        if result['rc'] == 0:
            cert_id = re.findall(r'Certificate ID: [\w]*', result['stdout'])[0]
            cert_id = cert_id.split(":")[1].strip()
            assert 'Approved certificate request {}'.format(request_id) in result['stdout']
            assert 'Request Status: complete' in result['stdout']
            log.info("Successfully ran: '{}'".format(result['cmd']))
        else:
            log.error(result['stderr'])
            pytest.fail('Failed to approve cert request')

    # Pretty print Certificate
    cmd = ansible_module.shell('pki -d {} -c {} -p {} -n "{}" ca-cert-show {} --pretty'.format(constants.NSSDB,
                                                                                    constants.CLIENT_DATABASE_PASSWORD,
                                                                                    constants.CA_HTTPS_PORT,
                                                                                    constants.CA_ADMIN_NICK, cert_id))
    for result in cmd.values():
        if result['rc'] == 0:
            assert "Identifier: Subject Alternative Name" in result['stdout']
            assert result['stdout'].count('DNSName') == 4
            log.info("Successfully ran: '{}'".format(result['cmd']))
        else:
            log.error(result['stderr'])
            pytest.fail('Failed to show cert details')
