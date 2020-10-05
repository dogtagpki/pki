#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description:  PKI CA Agent Requests tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Chandan Pinjani <cpinjani@redhat.com>
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
import datetime
import random
import time
import re
import pytest
import requests
import sys
import os
from pki.testlib.common.certlib import CertSetup, Setup
from pki.testlib.common.exceptions import PkiLibException
from pki.testlib.common.utils import UserOperations, ProfileOperations

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

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
ca_url = 'https://{}:{}'.format(constants.MASTER_HOSTNAME, constants.CA_HTTPS_PORT)
BASE_DIR = '/var/lib/pki/'
ca_cfg_path = BASE_DIR + '/' + instance + '/' + 'ca/conf/CS.cfg'
userop = UserOperations(nssdb=constants.NSSDB)
profop = ProfileOperations(nssdb=constants.NSSDB)
valid_agent_user = 'CA_AgentV'
valid_agent_cert = '/tmp/{}.pem'.format(valid_agent_user)
cert_setup = CertSetup(nssdb=constants.NSSDB, db_pass=constants.CLIENT_DATABASE_PASSWORD, host=constants.MASTER_HOSTNAME, port=constants.CA_HTTP_PORT, nick="'{}'".format(constants.CA_ADMIN_NICK))


def restart_instance(ansible_module, instance=instance):
    command = 'systemctl restart pki-tomcatd@{}'.format(instance)
    time.sleep(10)
    out = ansible_module.command(command)
    for res in out.values():
        assert res['rc'] == 0


def test_setup(ansible_module):
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
    ansible_module.shell('certutil -L -d {} -n "caSigningCert cert-{} CA" -a > /tmp/rootca.pem'.format(BASE_DIR + instance + "/alias", instance))
    ansible_module.fetch(src=valid_agent_cert, dest=valid_agent_cert, flat="yes")
    ansible_module.fetch(src='/tmp/rootca.pem', dest='/tmp/rootca.pem', flat="yes")


def test_ca_ag_profile_cert_request(ansible_module):
    """
    :id: c56faaac-7b25-47c5-8cda-0e767335cecf
    :Title: CA Agent Page: view a particular profile based certificate request
    :Description: CA Agent Page: view a particular profile based certificate request
    :Requirement: RHCS-REQ Certificate Authority Agent Services
    :CaseComponent: \-
    :Setup:
        1. Use the subsystems setup in ansible to run subsystem commands
        2. Use the CA setup certificate files to run CA Agent APIs
    :Steps:
        1. Create a Cert Request using python request module
        2. Check Request Status and request profile details
    :ExpectedResults:
        1.Certificate Request should raised successfully
        2.Certificate Request should have correct profile details
    """
    user_num = random.randint(1111111, 9999999)
    user_id = 'user{}'.format(user_num)
    pop_cert = "/tmp/{}".format(user_id)
    pop_out = ansible_module.shell('CRMFPopClient -d {} -p {} -a rsa -n "uid={}" -o {}'.format(constants.NSSDB, constants.CLIENT_DATABASE_PASSWORD, user_id, pop_cert))
    for result in pop_out.values():
        if result['rc'] == 0:
            ansible_module.fetch(src=pop_cert, dest=pop_cert, flat="yes")
            encoded_cert = open(pop_cert, "r").read()
        else:
            pytest.fail("Failed to run: {}".format("".join(result['cmd'])))

    # Create Certificate Request with Requests Module
    req_data = {
        'selectKeyType': 'RSA',
        'request_type': 'pkcs10',
        'sn_uid': user_id,
        'sn_cn': user_id,
        'sn_email': "{}@example.com".format(user_id),
        'requestor_name': user_id,
        'profileId': 'caUserCert',
        'cert_request_type': 'crmf',
        'cert_ext_exKeyUsageOIDs': '1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4',
        'cert_request': '{}'.format(encoded_cert)
    }
    response = requests.post(ca_url + "/ca/ee/ca/profileSubmit", data=req_data, verify='/tmp/rootca.pem', cert=valid_agent_cert)
    if response.status_code == 200:
        request = re.findall('requestList.requestId="[\w]*"', response.content)
        request_id = request[0].split("=")[1].strip().replace("\"", "")
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()

    cert_data = {'requestId': request_id}
    response = requests.post(ca_url + "/ca/agent/ca/profileReview", data=cert_data, verify='/tmp/rootca.pem', cert=valid_agent_cert)
    if response.status_code == 200:
        assert 'profileName="Manual User Dual-Use Certificate Enrollment"' in response.content
        assert 'inputList.inputVal="{}"'.format(user_id) in response.content
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()


def test_ca_ag_list_cert_request():
    """
    :id: 2b505d36-5539-41b4-947a-93ad60e9ca12
    :Title: CA Agent Page: List Requests try to display 100 requests and their details
    :Description: Check & list certificate requests details
    :Requirement: RHCS-REQ Certificate Authority Agent Services
    :CaseComponent: \-
    :Setup: Use the CA setup certificate files to run CA Agent APIs
    :Steps:
        1. Create a Cert Request using python request module
        2. Check Request Status and details
    :ExpectedResults:
        1.Certificate Request should raised successfully
        2.Certificate Request details should displayed successfully
    """
    req_data = {
        'reqType': 'enrollment',
        'reqState': 'showWaiting',
        'lastEntryOnPage': '0',
        'direction': 'first',
        'maxCount': '100'
    }
    response = requests.post(ca_url + "/ca/agent/ca/queryReq", data=req_data, verify='/tmp/rootca.pem', cert=valid_agent_cert)
    if response.status_code == 200:
        assert 'record.callerName="{}"'.format(valid_agent_user) in response.content
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()


def test_ca_ag_approve_request(ansible_module):
    """
    :id: d509a1e2-29d8-4ced-a36b-3f36ae4655d6
    :Title: CA Agent Page: Approve Profile request
    :Description: Create cert request by Profile and approve
    :Requirement: RHCS-REQ Certificate Authority Agent Services
    :CaseComponent: \-
    :Setup:
        1. Use the subsystems setup in ansible to run subsystem commands
        2. Use the CA setup certificate files to run CA Agent APIs
    :Steps:
        1. Create a Cert Request using python request module
        2. Check Request Status and profile details
        3. Check Request and approve
    :ExpectedResults:
        1.Certificate Request should raised successfully
        2.Certificate Request should be approved successfully
    """
    user_num = random.randint(1111111, 9999999)
    user_id = 'user{}'.format(user_num)
    pop_cert = "/tmp/{}".format(user_id)
    pop_out = ansible_module.shell('CRMFPopClient -d {} -p {} -a rsa -n "uid={}" -o {}'.format(constants.NSSDB, constants.CLIENT_DATABASE_PASSWORD, user_id, pop_cert))
    for result in pop_out.values():
        if result['rc'] == 0:
            ansible_module.fetch(src=pop_cert, dest=pop_cert, flat="yes")
            encoded_cert = open(pop_cert, "r").read()
        else:
            pytest.fail("Failed to run: {}".format("".join(result['cmd'])))

    req_data = {
        'selectKeyType': 'RSA',
        'request_type': 'pkcs10',
        'sn_uid': user_id,
        'sn_cn': user_id,
        'sn_email': "{}@example.com".format(user_id),
        'requestor_name': user_id,
        'profileId': 'caUserCert',
        'cert_request_type': 'crmf',
        'cert_ext_exKeyUsageOIDs': '1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4',
        'cert_request': '{}'.format(encoded_cert)
    }
    response = requests.post(ca_url + "/ca/ee/ca/profileSubmit", data=req_data, verify='/tmp/rootca.pem', cert=valid_agent_cert)
    if response.status_code == 200:
        request = re.findall('requestList.requestId="[\w]*"', response.content)
        request_id = request[0].split("=")[1].strip().replace("\"", "")
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()

    # Approve Above Request with request number with 60 Days expiry periods.
    req_data = {
        'requestId': '{}'.format(request_id),
        'op': 'approve',
        'submit': 'submit',
        'name': 'UID={}'.format(user_id),
        'authInfoAccessCritical': 'false',
        'notBefore': datetime.date.today().strftime("%Y-%m-%d %H:%M:%S"),
        'notAfter': (datetime.date.today() + datetime.timedelta(days=60)).strftime("%Y-%m-%d %H:%M:%S"),
        'authInfoAccessGeneralNames': '',
        'keyUsageCritical': 'true',
        'keyUsageDigitalSignature': 'true',
        'keyUsageNonRepudiation': 'true',
        'keyUsageKeyEncipherment': 'true',
        'keyUsageDataEncipherment': 'false',
        'keyUsageKeyAgreement': 'false',
        'keyUsageKeyCertSign': 'false',
        'keyUsageCrlSign': 'false',
        'keyUsageEncipherOnly': 'false',
        'keyUsageDecipherOnly': 'false',
        'exKeyUsageCritical': 'false',
        'exKeyUsageOIDs': '1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4',
        'subjAltNameExtCritical': 'false',
        'subjAltNames': 'RFC822Name:',
        'signingAlg': 'SHA1withRSA',
        'requestNotes': 'submittingcertfor{}'.format(user_id)
    }
    response = requests.post(ca_url + "/ca/agent/ca/profileProcess", data=req_data, verify='/tmp/rootca.pem', cert=valid_agent_cert)
    if response.status_code == 200:
        assert re.findall('Serial Number: [\w]*', response.content)
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()


@pytest.mark.parametrize('op', ['cancel', 'reject', 'assign', 'unassign', 'validate', 'update'])
def test_ca_ag_operate_request(ansible_module, op):
    """
    :id: beeb83fb-9b3f-4274-8dcb-b92dd347193f
    :parametrized: yes
    :Title: CA Agent Page: Operate on Certificate request
    :Description: Create cert request by Profile and operate it
    :Requirement: RHCS-REQ Certificate Authority Agent Services
    :CaseComponent: \-
    :Setup:
        1. Use the subsystems setup in ansible to run subsystem commands
        2. Use the CA setup certificate files to run CA Agent APIs
    :Steps:
        1. Create a Cert Request using python request module
        2. Check Request Status and profile details
        3. Check Request and perform operation
    :ExpectedResults:
        1.Certificate Request should raised successfully
        2.Certificate Request should be operated successfully
    """
    user_num = random.randint(1111111, 9999999)
    user_id = 'user{}'.format(user_num)
    pop_cert = "/tmp/{}".format(user_id)

    pop_out = ansible_module.shell('CRMFPopClient -d {} -p {} -a rsa -n "uid={}" -o {}'.format(constants.NSSDB, constants.CLIENT_DATABASE_PASSWORD, user_id, pop_cert))
    for result in pop_out.values():
        if result['rc'] == 0:
            ansible_module.fetch(src=pop_cert, dest=pop_cert, flat="yes")
            encoded_cert = open(pop_cert, "r").read()
        else:
            pytest.fail("Failed to run: {}".format("".join(result['cmd'])))

    req_data = {
        'selectKeyType': 'RSA',
        'request_type': 'pkcs10',
        'sn_uid': user_id,
        'sn_cn': user_id,
        'sn_email': "{}@example.com".format(user_id),
        'requestor_name': user_id,
        'profileId': 'caUserCert',
        'cert_request_type': 'crmf',
        'cert_ext_exKeyUsageOIDs': '1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4',
        'cert_request': '{}'.format(encoded_cert)
    }
    response = requests.post(ca_url + "/ca/ee/ca/profileSubmit", data=req_data, verify='/tmp/rootca.pem', cert=valid_agent_cert)
    if response.status_code == 200:
        request = re.findall('requestList.requestId="[\w]*"', response.content)
        request_id = request[0].split("=")[1].strip().replace("\"", "")
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()

    req_data = {
        'requestId': '{}'.format(request_id),
        'op': op,
        'submit': 'submit',
        'name': 'UID={}'.format(user_id),
        'authInfoAccessCritical': 'false',
        'authInfoAccessGeneralNames': '',
        'keyUsageCritical': 'true',
        'keyUsageDigitalSignature': 'true',
        'keyUsageNonRepudiation': 'true',
        'keyUsageKeyEncipherment': 'true',
        'keyUsageDataEncipherment': 'false',
        'keyUsageKeyAgreement': 'false',
        'keyUsageKeyCertSign': 'false',
        'keyUsageCrlSign': 'false',
        'keyUsageEncipherOnly': 'false',
        'keyUsageDecipherOnly': 'false',
        'exKeyUsageCritical': 'false',
        'exKeyUsageOIDs': '1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4',
        'subjAltNameExtCritical': 'false',
        'subjAltNames': 'RFC822Name:',
        'signingAlg': 'SHA1withRSA',
        'requestNotes': 'submittingcertfor{}'.format(user_id)
    }
    response = requests.post(ca_url + "/ca/agent/ca/profileProcess", data=req_data, verify='/tmp/rootca.pem', cert=valid_agent_cert)
    if response.status_code == 200:
        if op == 'cancel':
            assert 'requestId="{}"'.format(request_id) in response.content
            assert 'requestStatus="canceled"' in response.content
        elif op == 'reject':
            assert 'requestId="{}"'.format(request_id) in response.content
            assert 'requestStatus="rejected"' in response.content
        else:
            assert 'requestId="{}"'.format(request_id) in response.content
            assert 'requestStatus="pending"' in response.content
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()


def test_ca_ag_search_certs_with_serial():
    """
    :id: d0d811c5-1fb0-4b91-ae9f-080886bf4fda
    :Title: Search certs with serial Number range
    :Description: Search certs with serial Number range
    :Requirement: RHCS-REQ Certificate Authority Agent Services
    :CaseComponent: \-
    :Setup: Use the CA setup certificate files to run CA Agent APIs
    :Steps:
        1. Search certificate with serial Number range filter
    :ExpectedResults:
        1.Certificate details should displayed successfully
    """
    req_data = {
        'op': 'srchCerts',
        'serialNumberRangeInUse': "on",
        'serialFrom': 0,
        'serialTo': 300,
        'status': 'VALID',
        'match': 'partial',
        'queryCertFilter': "(&(certRecordId>=$serialFrom)(certRecordId<=$serialTo))",
        'unit': "2592000000",
        'maxResults': '10',
        'timeLimit': '5',
    }
    response = requests.post(ca_url + "/ca/agent/ca/srchCerts", data=req_data, verify='/tmp/rootca.pem', cert=valid_agent_cert)
    if response.status_code == 200 and response.content.count("record.subject=") == 10:
        assert re.findall('record.serialNumberDecimal="[\w]*"', response.content)
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()


def test_ca_ag_search_valid_certs():
    """
    :id: 2eca12e7-f276-4833-95b3-668e65e190e5
    :Title: Search certs with valid status
    :Description: Search certs with status valid
    :Requirement: RHCS-REQ Certificate Authority Agent Services
    :CaseComponent: \-
    :Setup: Use the CA setup certificate files to run CA Agent APIs
    :Steps:
        1. Search certificate with valid status filter
    :ExpectedResults:
        1.Certificate details should displayed successfully
    """
    req_data = {
        'op': 'srchCerts',
        'statusInUse': 'on',
        'status': 'VALID',
        'match': 'partial',
        'queryCertFilter': "(&(certStatus=VALID))",
        'unit': "2592000000",
        'maxResults': '1000',
        'timeLimit': '5',
    }
    response = requests.post(ca_url + "/ca/agent/ca/srchCerts", data=req_data, verify='/tmp/rootca.pem', cert=valid_agent_cert)
    if response.status_code == 200 and response.content.count("record.subject=") > 10:
        assert re.findall('record.serialNumberDecimal="[\w]*"', response.content)
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()


def test_ca_ag_search_revoked_certs(ansible_module):
    """
    :id: c09d75c8-8b47-4cc0-88dd-5a8aa5a4a7a8
    :Title: Search certs with revoked status
    :Description: Search certs with status revoked
    :Requirement: RHCS-REQ Certificate Authority Agent Services
    :CaseComponent: \-
    :Setup:
        1. Use the subsystems setup in ansible to run subsystem commands
        2. Use the CA setup certificate files to run CA Agent APIs
    :Steps:
        1. Create a Cert Request using python request module
        2. Check Request Status and profile details
        3. Check Request and perform revoke
        4. Search certificate with revoked status filter
        5. Search certificate with revoked status filter by agent
    :ExpectedResults:
        1.Certificate Request should raised successfully
        2.Certificate Request should be revoked successfully
        3.Certificate details should displayed successfully
    """

    user_num = random.randint(1111111, 9999999)
    user_id = 'user{}'.format(user_num)
    pop_cert = "/tmp/{}".format(user_id)
    pop_out = ansible_module.shell('CRMFPopClient -d {} -p {} -a rsa -n "uid={}" -o {}'.format(constants.NSSDB, constants.CLIENT_DATABASE_PASSWORD, user_id, pop_cert))
    for result in pop_out.values():
        if result['rc'] == 0:
            ansible_module.fetch(src=pop_cert, dest=pop_cert, flat="yes")
            encoded_cert = open(pop_cert, "r").read()
        else:
            pytest.fail("Failed to run: {}".format("".join(result['cmd'])))

    req_data = {
        'selectKeyType': 'RSA',
        'request_type': 'pkcs10',
        'sn_uid': user_id,
        'sn_cn': user_id,
        'sn_email': "{}@example.com".format(user_id),
        'requestor_name': user_id,
        'profileId': 'caUserCert',
        'cert_request_type': 'crmf',
        'cert_ext_exKeyUsageOIDs': '1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4',
        'cert_request': '{}'.format(encoded_cert)
    }
    response = requests.post(ca_url + "/ca/ee/ca/profileSubmit", data=req_data, verify='/tmp/rootca.pem', cert=valid_agent_cert)
    if response.status_code == 200:
        request = re.findall('requestList.requestId="[\w]*"', response.content)
        request_id = request[0].split("=")[1].strip().replace("\"", "")
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()

    req_approval_data = {
        'requestId': '{}'.format(request_id),
        'op': 'approve',
        'submit': 'submit',
        'name': 'UID={}'.format(user_id),
        'notBefore': datetime.date.today().strftime("%Y-%m-%d %H:%M:%S"),
        'notAfter': (datetime.date.today() + datetime.timedelta(days=15)).strftime("%Y-%m-%d %H:%M:%S"),
        'authInfoAccessCritical': 'false',
        'authInfoAccessGeneralNames': '',
        'keyUsageCritical': 'true',
        'keyUsageDigitalSignature': 'true',
        'keyUsageNonRepudiation': 'true',
        'keyUsageKeyEncipherment': 'true',
        'keyUsageDataEncipherment': 'false',
        'keyUsageKeyAgreement': 'false',
        'keyUsageKeyCertSign': 'false',
        'keyUsageCrlSign': 'false',
        'keyUsageEncipherOnly': 'false',
        'keyUsageDecipherOnly': 'false',
        'exKeyUsageCritical': 'false',
        'exKeyUsageOIDs': '1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4',
        'subjAltNameExtCritical': 'false',
        'subjAltNames': 'RFC822Name:',
        'signingAlg': 'SHA1withRSA',
        'requestNotes': 'submittingcertfor{}'.format(user_id)
    }
    response = requests.post(ca_url + "/ca/agent/ca/profileProcess", data=req_approval_data, verify='/tmp/rootca.pem', cert=valid_agent_cert)
    if response.status_code == 200:
       cert_detail = re.findall('Serial Number: [\w]*', response.content)
       cert_serial = cert_detail[0].split(":")[1].strip().replace("\"", "")
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()

    out = ansible_module.shell('echo "Y" | pki -d {} -c {} -p {} -n {} ca-cert-revoke {}'.format(constants.NSSDB, constants.CLIENT_DATABASE_PASSWORD, constants.CA_HTTPS_PORT, valid_agent_user, cert_serial))
    for result in out.values():
        if result['rc'] == 0:
            assert 'Serial Number: {}'.format(cert_serial.lower()) in result['stdout']
            assert 'REVOKED' in result['stdout']
        else:
            pytest.fail("Failed to run: {}".format("".join(result['cmd'])))

    req_data = {
        'op': 'srchCerts',
        'statusInUse': 'on',
        'status': 'REVOKED',
        'match': 'partial',
        'queryCertFilter': "(&(certStatus=REVOKED))",
        'unit': "2592000000",
        'maxResults': '1000',
        'timeLimit': '5',
    }
    response = requests.post(ca_url + "/ca/agent/ca/srchCerts", data=req_data, verify='/tmp/rootca.pem', cert=valid_agent_cert)
    if response.status_code == 200:
       log.info("Successfully run: {}".format(response.status_code))
       assert 'record.revokedOn=null' not in response.content
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()

    req_data = {
        'op': 'srchCerts',
        'match': 'partial',
        'revokedBy': valid_agent_user,
        'revokedByInUse': 'on',
        'queryCertFilter': "(&(certRevokedBy={}))".format(valid_agent_user),
        'unit': "2592000000",
        'maxResults': '1000',
        'timeLimit': '5',
    }
    response = requests.post(ca_url + "/ca/agent/ca/srchCerts", data=req_data, verify='/tmp/rootca.pem', cert=valid_agent_cert)
    if response.status_code == 200 and response.content.count("record.subject") > 1:
        assert 'record.revokedOn=null' not in response.content
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()

    req_data = {
        'op': 'srchCerts',
        'match': 'partial',
        'revocationReasonInUse': 'on',
        'revocationReason': '0',
        'queryCertFilter': "(&(x509cert.certRevoInfo=0))",
        'unit': "2592000000",
        'maxResults': '1000',
        'timeLimit': '5',
    }
    response = requests.post(ca_url + "/ca/agent/ca/srchCerts", data=req_data, verify='/tmp/rootca.pem', cert=valid_agent_cert)
    if response.status_code == 200 and response.content.count("record.subject") > 1:
        assert 'record.revokedOn=null' not in response.content
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()


def test_ca_ag_profile_1day_validity_search_certs(ansible_module):
    """
    :id: 1a83dc22-ae9b-4069-bcba-5da939c77516
    :Title: Generate a profile which generates cert with 1 day validity period
    :Description: Generate a profile which generates cert with 1 day validity period
    :Requirement: RHCS-REQ Certificate Authority Agent Services
    :CaseComponent: \-
    :Setup:
        1. Use the subsystems setup in ansible to run subsystem commands
        2. Use the CA setup certificate files to run CA Agent APIs
    :Steps:
        1. Create profile with property of validity 1 day
        2. Create a Cert Request using python request module
        3. Check Request Status and profile details
        4. Check Request and perform approve
        5. Search certificate with expired status filter
        6. Search certificate with subject name
    :ExpectedResults:
        1.Profile should be generated successfully
        1.Certificate Request should raised successfully
        2.Certificate Request should be approved successfully
        3.Certificate must be expired after 1 day
        4.Certificate details should displayed successfully
    """

    # Create the profile
    num = random.randint(1111111, 9999999)
    user = 'testcaUserCert{}'.format(num)
    fullName = '{} User'.format(user)
    subject = "UID={},CN={}".format(user, fullName)
    profile = "caUserCert{}".format(num)
    profile_xml_output = '/tmp/{}.xml'.format(profile)
    prof = Setup(profile_type='user', profile_id=profile)
    profile_param = {'ProfileName': '{} Enrollment Profile'.format(profile),
                     'notBefore': '1',
                     'notAfter': '1',
                     'ValidFor': '1',
                     'rangeunit': 'day',
                     'MaxValidity': '1'}
    output_list = prof.create_profile(profile_param)
    log.info("Successfully created profile param'{}'".format(output_list[0]))
    ansible_module.copy(src=output_list[0], dest=profile_xml_output, force=True)
    # Add the profile
    cmd_out = ansible_module.pki(cli="ca-profile-add", nssdb=constants.NSSDB, dbpassword=constants.CLIENT_DATABASE_PASSWORD, port=constants.CA_HTTP_PORT, hostname=constants.MASTER_HOSTNAME, certnick='"{}"'.format(constants.CA_ADMIN_NICK), extra_args='{}'.format(profile_xml_output))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Added profile {}".format(profile) in result['stdout']
            assert "Profile ID: {}".format(profile) in result['stdout']
            log.info("Successfully ran: '{}'".format(result['cmd']))
        else:
            log.info("Failed to ran: '{}'".format(result['cmd']))
            pytest.fail()
    # Enable the profile
    try:
        assert cert_setup.enable_profile(ansible_module, profile)
        log.info("Successfully enabled the profile : {}".format(profile))
    except PkiLibException as err:
        log.error("Unable to enable profile, failed with error: '{}'".format(err.msg))
        pytest.fail()

    # Create Cert request which satify name pattern
    try:
        cert_serial = userop.process_certificate_request(ansible_module, subject=subject, profile=profile)
        log.info("Successfully created Cert ID: {}".format(cert_serial))
    except PkiLibException as err:
        log.error("Unable to enroll cert : '{}'".format(err.msg))
        pytest.fail()
    cert_serial_file = cert_setup.cert_show(ansible_module, cert_serial)[1]
    cert_file = "/tmp/{}.pem".format(cert_serial)
    ansible_module.fetch(src=cert_serial_file, dest=cert_file, flat=True)
    cert_attributes = cert_setup.cert_attributes(cert_file)
    validity = cert_attributes['notAfter_strformat'] - cert_attributes['notBefore_strformat']
    assert '1 day, 0:00:00' == str(validity)
    log.info("Successfully created profile valid for 1 day")

    out = ansible_module.shell('pki -d {} -c {} -p {} -n "{}" ca-cert-show {}'.format(constants.NSSDB, constants.CLIENT_DATABASE_PASSWORD, constants.CA_HTTPS_PORT, valid_agent_user, cert_serial))
    for result in out.values():
        if result['rc'] == 0:
            assert 'VALID' in result['stdout']
            assert 'Serial Number: {}'.format(cert_serial.lower()) in result['stdout']
        else:
            pytest.fail("Failed to run: {}".format(" ".join(result['cmd'])))

    out = ansible_module.shell('pki -d {} -c {} -p {} -n {} client-cert-import --serial {}'.format(constants.NSSDB,constants.CLIENT_DATABASE_PASSWORD, constants.CA_HTTPS_PORT, user, cert_serial))
    for result in out.values():
        if result['rc'] == 0:
            assert 'Imported certificate "{}"'.format(user) in result['stdout']
        else:
            pytest.fail("Failed to run: {}".format(" ".join(result['cmd'])))

    out = ansible_module.shell("date")
    cur_clock = out.values()[0]['stdout']

    out = ansible_module.shell("chronyc -a 'manual on' ; chronyc -a -m 'offline' 'settime + 1 day' 'makestep' 'manual reset'")
    for result in out.values():
        if result['rc'] == 0:
            log.info("Successfully changed system date ahead by 1 day")
        else:
            pytest.fail("Failed to run: {}".format("".join(result['cmd'])))

    restart_instance(ansible_module)

    out = ansible_module.shell('pki -d {} -c {} -p {} -n "{}" ca-cert-show {}'.format(constants.NSSDB, constants.CLIENT_DATABASE_PASSWORD, constants.CA_HTTPS_PORT, valid_agent_user, cert_serial))
    for result in out.values():
        if result['rc'] == 0:
            assert 'EXPIRED' in result['stdout']
            assert 'Serial Number: {}'.format(cert_serial.lower()) in result['stdout']
        else:
            pytest.fail("Failed to run: {}".format("".join(result['cmd'])))

    req_data = {
        'op': 'srchCerts',
        'statusInUse': 'on',
        'status': 'EXPIRED',
        'match': 'partial',
        'queryCertFilter': "(&(certStatus=EXPIRED))",
        'unit': "2592000000",
        'maxResults': '1000',
        'timeLimit': '5',
    }
    response = requests.post(ca_url + "/ca/agent/ca/srchCerts", data=req_data, verify='/tmp/rootca.pem', cert=valid_agent_cert)
    if response.status_code == 200:
       assert 'record.subject="{}"'.format(subject) in response.content
       log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()

    req_data = {
        'op': 'srchCerts',
        'subjectInUse': 'on',
        'status': 'VALID',
        'match': 'partial',
        'commonName': fullName,
        'queryCertFilter': "(&(&(|(x509Cert.subject=*CN={},*)(x509Cert.subject=*CN={}))))".format(fullName, fullName),
        'unit': "2592000000",
        'maxResults': '1000',
        'timeLimit': '5',
    }
    response = requests.post(ca_url + "/ca/agent/ca/srchCerts", data=req_data, verify='/tmp/rootca.pem', cert=valid_agent_cert)
    if response.status_code == 200:
        assert 'record.subject="{}"'.format(subject) in response.content
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()

    cmd = "chronyc -a -m 'settime {} + 20 seconds' 'makestep' 'manual reset' 'online'".format(cur_clock)
    out = ansible_module.shell(cmd)
    for result in out.values():
        if result['rc'] == 0:
            log.info("Successfully restored system date")
        else:
            pytest.fail("Failed to run: {}".format("".join(result['cmd'])))


def test_ca_ag_search_certs_issued_by_agent():
    """
    :id: 29ec50a2-be8e-4827-a738-5968c7794a40
    :Title: Search certs issued by valid agent
    :Description: Search certs issued by valid agent
    :Requirement: RHCS-REQ Certificate Authority Agent Services
    :CaseComponent: \-
    :Setup: Use the CA setup certificate files to run CA Agent APIs
    :Steps:
        1. Search certs issued by valid agent filter
    :ExpectedResults:
        1.Certificate details should displayed successfully
    """
    req_data = {
        'op': 'srchCerts',
        'match': 'partial',
        'issuedByInUse': 'on',
        'issuedBy': valid_agent_user,
        'queryCertFilter': "(&(certIssuedBy={}))".format(valid_agent_user),
        'unit': "2592000000",
        'maxResults': '1000',
        'timeLimit': '5',
    }
    response = requests.post(ca_url + "/ca/agent/ca/srchCerts", data=req_data, verify='/tmp/rootca.pem', cert=valid_agent_cert)
    if response.status_code == 200 and response.content.count("record.subject") > 1:
        assert 'record.revokedOn=null' in response.content
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()


def test_ca_ag_search_certs_1day_validity():
    """
    :id: 21c7ecf5-5201-4518-b045-70fb17fb190e
    :Title: Search certs having validity of 1 day
    :Description: Search certs having validity of 1 day
    :Requirement: RHCS-REQ Certificate Authority Agent Services
    :CaseComponent: \-
    :Setup: Use the CA setup certificate files to run CA Agent APIs
    :Steps:
        1. Search certs having validity of 1 day filter
    :ExpectedResults:
        1.Certificate details should displayed successfully
    """
    req_data = {
        'op': 'srchCerts',
        'match': 'partial',
        'queryCertFilter': "(&(x509cert.duration<=86400000))",
        'validityLengthInUse': 'on',
        'validityOp': '<=',
        'count': '1',
        'unit': '86400000',
        'maxResults': '1000',
        'timeLimit': '5',
    }
    response = requests.post(ca_url + "/ca/agent/ca/srchCerts", data=req_data, verify='/tmp/rootca.pem', cert=valid_agent_cert)
    if response.status_code == 200 and response.content.count("record.subject") > 1:
        assert 'record.revokedOn=null' in response.content
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()


def test_ca_ag_search_certs_basic_contraints():
    """
    :id: 9d31837b-f449-4cdb-98b7-500878051bf1
    :Title: Search certs with Basic Contraints
    :Description: Search certs with Basic Contraints
    :Requirement: RHCS-REQ Certificate Authority Agent Services
    :CaseComponent: \-
    :Setup: Use the CA setup certificate files to run CA Agent APIs
    :Steps:
        1. Search certs with Basic Contraints filter
    :ExpectedResults:
        1.Certificate details should displayed successfully
    """
    req_data = {
        'op': 'srchCerts',
        'match': 'partial',
        'queryCertFilter': "(&(x509cert.BasicConstraints.isCA=on))",
        'basicConstraintsInUse': 'on',
        'unit': '2592000000',
        'maxResults': '1000',
        'timeLimit': '5',
    }
    response = requests.post(ca_url + "/ca/agent/ca/srchCerts", data=req_data, verify='/tmp/rootca.pem', cert=valid_agent_cert)
    if response.status_code == 200 and response.content.count("record.subject") > 1:
        assert 'record.revokedOn=null' in response.content
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()


def test_ca_ag_generate_netscape_profile_search_cert(ansible_module):
    """
    :id: 56c89a71-c094-47aa-a23d-e13bd5db2b24
    :Title: Generate a profile with Netscape Extensions
    :Description: Generate a profile with Netscape Extensions
    :Requirement: RHCS-REQ Certificate Authority Agent Services
    :CaseComponent: \-
    :Setup:
        1. Use the subsystems setup in ansible to run subsystem commands
        2. Use the CA setup certificate files to run CA Agent APIs
    :Steps:
        1. Create profile with Netscape Extensions
        2. Create a Cert Request using python request module
        3. Check Request Status and profile details
        4. Check Request and perform approve
        5. Search certificate with ssl filter
    :ExpectedResults:
        1.Profile should be generated successfully
        1.Certificate Request should raised successfully
        2.Certificate Request should be approved successfully
        4.Certificate details should displayed successfully
    """

    # Create the profile
    user_num = random.randint(1111111, 9999999)
    user = 'testcaUserCert{}'.format(user_num)
    fullName = '{} User'.format(user)
    subject = "UID={},CN={}".format(user, fullName)
    profile = "caUserCert{}".format(user_num)
    profile_xml_output = '/tmp/{}.xml'.format(profile)
    prof = Setup(profile_type='user', profile_id=profile)
    profile_param = {'ProfileName': '{} Enrollment Profile'.format(profile),
                     'NetscapeExtensions': '''
                      nsCertCritical,
                      nsCertSSLClient,
                      nsCertEmail'''}
    output_list = prof.create_profile(profile_param)
    log.info("Successfully created profile param'{}'".format(output_list[0]))
    ansible_module.copy(src=output_list[0], dest=profile_xml_output, force=True)
    # Add the profile
    cmd_out = ansible_module.pki(cli="ca-profile-add", nssdb=constants.NSSDB, dbpassword=constants.CLIENT_DATABASE_PASSWORD, port=constants.CA_HTTP_PORT, hostname=constants.MASTER_HOSTNAME, certnick='"{}"'.format(constants.CA_ADMIN_NICK), extra_args='{}'.format(profile_xml_output))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Added profile {}".format(profile) in result['stdout']
            assert "Profile ID: {}".format(profile) in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.fail()
    # Enable the profile
    try:
        assert cert_setup.enable_profile(ansible_module, profile)
        log.info("Successfully enabled the profile : {}".format(profile))
    except PkiLibException as err:
        log.error("Unable to enable profile, failed with error: '{}'".format(err.msg))
        pytest.fail()

    # Create Cert request which satify name pattern
    try:
        cert_serial = userop.process_certificate_request(ansible_module, subject=subject, profile=profile)
        log.info("Successfully created Cert ID: {}".format(cert_serial))
    except PkiLibException as err:
        log.error("Unable to enroll cert: '{}'".format(err.msg))
        pytest.fail()
    cert_serial_file = cert_setup.cert_show(ansible_module, cert_serial)[1]
    cert_file = "/tmp/{}.pem".format(cert_serial)
    ansible_module.fetch(src=cert_serial_file, dest=cert_file, flat=True)
    cert_attributes = cert_setup.cert_attributes(cert_file)
    assert 'SSL Client, S/MIME' in cert_attributes['extensions']
    log.info("Successfully created profile with netscape extensions")

    out = ansible_module.shell('pki -d {} -c {} -p {} -n "{}" ca-cert-show {}'.format(constants.NSSDB, constants.CLIENT_DATABASE_PASSWORD, constants.CA_HTTPS_PORT, valid_agent_user, cert_serial))
    for result in out.values():
        if result['rc'] == 0:
            assert 'VALID' in result['stdout']
            assert 'Serial Number: {}'.format(cert_serial.lower()) in result['stdout']
        else:
            pytest.fail("Failed to run: {}".format("".join(result['cmd'])))

    out = ansible_module.shell('pki -d {} -c {} -p {} -n {} client-cert-import --serial {}'.format(constants.NSSDB,constants.CLIENT_DATABASE_PASSWORD, constants.CA_HTTPS_PORT, user, cert_serial))

    for result in out.values():
        if result['rc'] == 0:
            log.info("Successfully imported certificate: {}".format(cert_serial))
        else:
            pytest.fail("Failed to run: {}".format(" ".join(result['cmd'])))

    out = ansible_module.shell('pki -d {} -c {} -p {} -n "{}" ca-cert-show {} --pretty'.format(constants.NSSDB, constants.CLIENT_DATABASE_PASSWORD, constants.CA_HTTPS_PORT, valid_agent_user, cert_serial))
    for result in out.values():
        if result['rc'] == 0:
            assert 'Identifier: Netscape Certificate Type - 2.16.840.1.113730.1.1' in result['stdout']
            assert 'Serial Number: {}'.format(cert_serial.lower()) in result['stdout']
        else:
            pytest.fail("Failed to run: {}".format(" ".join(result['cmd'])))

    req_data = {
        'op': 'srchCerts',
        'match': 'partial',
        'queryCertFilter': "(&(x509cert.nsExtension.SSLClient=on))",
        'certTypeInUse': 'on',
        'SSLClient': 'on',
        'unit': '2592000000',
        'maxResults': '100',
        'timeLimit': '5',
    }
    response = requests.post(ca_url + "/ca/agent/ca/srchCerts", data=req_data, verify='/tmp/rootca.pem', cert=valid_agent_cert)
    if response.status_code == 200:
        assert 'record.revokedOn=null' in response.content
        assert 'record.subject="{}"'.format(subject) in response.content
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()


def test_clean_setup(ansible_module):
    for i in os.listdir('/tmp/'):
        if os.path.isfile(i):
            os.remove("/tmp/{}".format(i))
    ansible_module.lineinfile(path=ca_cfg_path, regexp="ca.enableNonces=false", line="ca.enableNonces=true")
    restart_instance(ansible_module)
