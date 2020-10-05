#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description:  PKI CA Agent Profile tests
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
import pytest
import random
import requests
import os
import sys
import re
import datetime
import time

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
valid_agent_user = 'CA_AgentV'
valid_agent_cert = '/tmp/{}.pem'.format(valid_agent_user)
valid_admin_user = 'CA_AdminV'
valid_admin_cert = '/tmp/{}.pem'.format(valid_admin_user)
valid_audit_user = 'CA_AuditV'
valid_audit_cert = '/tmp/{}.pem'.format(valid_audit_user)
user_num = random.randint(1111111, 9999999)
profile = 'caUserCert{}'.format(user_num)
sets = ['set1:p1', 'set1:p2', 'set1:p3', 'set1:p4', 'set1:p5', 'set1:p6', 'set1:p7', 'set1:p8', 'set1:p9', 'set1:p10']


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
        1. Create a valid Agent, Admin, Audit and CA Signing certificate pem files
        2. Disable Nonces property
        3. Change admin user password
    :Expected Results:
       1. Nonces property is disabled
       2. Valid Agent, Admin, Audit and CA Signing certificate pem files are created to be used in request module
       3. Password for admin user changed successfully
    """
    ansible_module.lineinfile(path=ca_cfg_path, regexp="ca.enableNonces=true", line="ca.enableNonces=false")
    restart_instance(ansible_module)
    log.info("Restarted instance : {}".format(instance))
    ansible_module.shell('certutil -L -d {} -n "caSigningCert cert-{} CA" -a > /tmp/rootca.pem'.format(BASE_DIR + instance + "/alias", instance))
    ansible_module.fetch(src='/tmp/rootca.pem', dest='/tmp/rootca.pem', flat="yes")

    out = ansible_module.shell('pki -p {} -d {} -c {} -n "{}" ca-user-mod {} --password {}'.format(constants.CA_HTTPS_PORT, constants.NSSDB, constants.CLIENT_DATABASE_PASSWORD, constants.CA_ADMIN_NICK, valid_admin_user, constants.CLIENT_DATABASE_PASSWORD))
    for result in out.values():
        if result['rc'] == 0:
            log.info("Successfully modified admin user password")
        else:
            pytest.fail("Failed to run: {}".format("".join(result['cmd'])))


@pytest.mark.parametrize('users', ['CA_AgentV', 'CA_AdminV', 'CA_AuditV'])
def test_setup_certs(ansible_module, users):
    ansible_module.shell('pki -d {} -c {} pkcs12-cert-import {} --pkcs12-file /tmp/{}.p12 --pkcs12-password {}'.format(constants.NSSDB, constants.CLIENT_DATABASE_PASSWORD, users, users, constants.CLIENT_DATABASE_PASSWORD))
    ansible_module.shell("openssl pkcs12 -in /tmp/{}.p12 -out /tmp/{}.pem -nodes -passin pass:{}".format(users, users, constants.CLIENT_DATABASE_PASSWORD))
    ansible_module.fetch(src='/tmp/{}.pem'.format(users), dest='/tmp/{}.pem'.format(users), flat="yes")


def test_ca_ag_add_profile_input_params():
    """
    :id: 7041623c-5b74-493e-b467-434a696c3576
    :Title: CA Admin Interface - Create a new profile rules with caEnrollImpl
    :Description: CA Admin Interface - Create a new profile rules with caEnrollImpl, Key Generation Input, subject Name Input, Requestor Information Input, Certificate Output
    :Requirement: RHCS-REQ Certificate Authority Agent Services
    :CaseComponent: \-
    :Setup: Use the CA setup certificate files to run CA Agent APIs
    :Steps:
        1. Create new profile rules
        2. Add input parameters to profile
    :ExpectedResults:
        1.Profile rules should be created successfully
        2.Input parameters should be added to profile successfully
    """
    # Create new profile
    req_data = {
        'OP_TYPE': 'OP_ADD',
        'OP_SCOPE': 'rules',
        'RS_ID': profile,
        'impl': 'caEnrollImpl',
        'name': profile,
        'visible': 'true',
        'desc': profile
    }
    response = requests.post(ca_url + '/ca/caprofile', data=req_data, verify=False, auth=(valid_admin_user, constants.CA_PASSWORD))
    if response.status_code == 200:
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()

    req_data = {
        'OP_TYPE': 'OP_SEARCH',
        'OP_SCOPE': 'rules',
    }
    response = requests.post(ca_url + '/ca/caprofile', data=req_data, verify=False, auth=(valid_admin_user, constants.CA_PASSWORD))
    if response.status_code == 200:
        text = response.text.encode('utf-8').replace('%3B', b':')
        assert '{}={}:visible:disabled'.format(profile, profile) in text
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()

    # Add Key Generation Input
    req_data = {
        'OP_TYPE': 'OP_ADD',
        'OP_SCOPE': 'profileInput',
        'RS_ID': '{};i1;keyGenInputImpl'.format(profile)
    }
    response = requests.post(ca_url + '/ca/caprofile', data=req_data, verify=False, auth=(valid_admin_user, constants.CA_PASSWORD))
    if response.status_code == 200:
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()

    req_data = {
        'OP_TYPE': 'OP_READ',
        'OP_SCOPE': 'profileInput',
        'RS_ID': profile
    }
    response = requests.post(ca_url + '/ca/caprofile', data=req_data, verify=False, auth=(valid_admin_user, constants.CA_PASSWORD))
    if response.status_code == 200:
        assert 'i1=Key+Generation' in response.content
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()

    # Add Subject Name Input
    req_data = {
        'OP_TYPE': 'OP_ADD',
        'OP_SCOPE': 'profileInput',
        'RS_ID': '{};i2;subjectNameInputImpl'.format(profile),
        'sn_uid': 'true',
        'sn_e': 'true',
        'sn_cn': 'true',
        'sn_ou3': 'true',
        'sn_ou2': 'true',
        'sn_ou1': 'true',
        'sn_ou': 'true',
        'sn_o': 'true',
        'sn_c': 'true'
    }
    response = requests.post(ca_url + '/ca/caprofile', data=req_data, verify=False, auth=(valid_admin_user, constants.CA_PASSWORD))
    if response.status_code == 200:
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()

    req_data = {
        'OP_TYPE': 'OP_READ',
        'OP_SCOPE': 'profileInput',
        'RS_ID': profile
    }
    response = requests.post(ca_url + '/ca/caprofile', data=req_data, verify=False, auth=(valid_admin_user, constants.CA_PASSWORD))
    if response.status_code == 200:
        assert 'i2=Subject+Name' in response.content
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()

    # Add Requestor Information
    req_data = {
        'OP_TYPE': 'OP_ADD',
        'OP_SCOPE': 'profileInput',
        'RS_ID': '{};i3;submitterInfoInputImpl'.format(profile)
    }
    response = requests.post(ca_url + '/ca/caprofile', data=req_data, verify=False, auth=(valid_admin_user, constants.CA_PASSWORD))
    if response.status_code == 200:
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()

    req_data = {
        'OP_TYPE': 'OP_READ',
        'OP_SCOPE': 'profileInput',
        'RS_ID': profile
    }
    response = requests.post(ca_url + '/ca/caprofile', data=req_data, verify=False, auth=(valid_admin_user, constants.CA_PASSWORD))
    if response.status_code == 200:
        assert 'i3=Requestor+Information' in response.content
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()

    # Add Certificate Output
    req_data = {
        'OP_TYPE': 'OP_ADD',
        'OP_SCOPE': 'profileOutput',
        'RS_ID': '{};o1;certOutputImpl'.format(profile)
    }
    response = requests.post(ca_url + '/ca/caprofile', data=req_data, verify=False, auth=(valid_admin_user, constants.CA_PASSWORD))
    if response.status_code == 200:
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()

    req_data = {
        'OP_TYPE': 'OP_READ',
        'OP_SCOPE': 'profileOutput',
        'RS_ID': profile
    }
    response = requests.post(ca_url + '/ca/caprofile', data=req_data, verify=False, auth=(valid_admin_user, constants.CA_PASSWORD))
    if response.status_code == 200:
        assert 'o1=Certificate+Output' in response.content
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()


@pytest.mark.parametrize('profile_set', sets)
def test_ca_ag_add_profile_policies(profile_set):
    """
    :id: 1761c3c0-5d1e-4f50-ad4e-9127e51466e5
    :parametrized: yes
    :Title: CA Admin Interface - Create a new profile policies as Admin Only user
    :Description: CA Admin Interface - Create a new profile policies as Admin Only user
    :Requirement: RHCS-REQ Certificate Authority Agent Services
    :CaseComponent: \-
    :Setup: Use the CA setup certificate files to run CA Agent APIs
    :Steps:
        1. Create new profile policies
        2. Add parameters to profile
    :ExpectedResults:
        1.Profile policies should be created successfully
        2.Policy parameters should be added to profile successfully
    """
    if profile_set == 'set1:p1':
        policy = 'userSubjectNameDefaultImpl'
        constraint = 'subjectNameConstraintImpl'
        defaultpolicy_data = {}
        constraintpolicy_data = {'pattern': 'UID=.*'}

    elif profile_set == 'set1:p2':
        policy = 'noDefaultImpl'
        constraint = 'renewGracePeriodConstraintImpl'
        defaultpolicy_data = {}
        constraintpolicy_data = {'renewal.graceBefore': '30', 'renewal.graceAfter': '30'}

    elif profile_set == 'set1:p3':
        policy = 'validityDefaultImpl'
        constraint = 'validityConstraintImpl'
        defaultpolicy_data = {'range': '180', 'startTime': '0'}
        constraintpolicy_data = {'range': '365', 'notBeforeGracePeriod': '0', 'notBeforeCheck': 'false', 'notAfterCheck': 'false'}

    elif profile_set == 'set1:p4':
        policy = 'extendedKeyUsageExtDefaultImpl'
        constraint = 'noConstraintImpl'
        defaultpolicy_data = {'exKeyUsageCritical': 'false', 'exKeyUsageOIDs': '1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4'}
        constraintpolicy_data = {}

    elif profile_set == 'set1:p5':
        policy = 'subjectAltNameExtDefaultImpl'
        constraint = 'noConstraintImpl'
        defaultpolicy_data = {'subjAltNameExtCritical': 'false', 'subjAltNameNumGNs': '1', 'subjAltExtType_0': 'RFC822Name', 'subjAltExtPattern_0': '$request.requestor_email$', 'subjAltExtGNEnable_0': 'false'}
        constraintpolicy_data = {}

    elif profile_set == 'set1:p6':
        policy = 'userKeyDefaultImpl'
        constraint = 'keyConstraintImpl'
        defaultpolicy_data = {}
        constraintpolicy_data = {'keyType': '-', 'keyParameters': '1024,2048,3072,4096,nistp256,nistp384,nistp521'}

    elif profile_set == 'set1:p7':
        policy = 'authorityKeyIdentifierExtDefaultImpl'
        constraint = 'noConstraintImpl'
        defaultpolicy_data = {}
        constraintpolicy_data = {}

    elif profile_set == 'set1:p8':
        policy = 'authInfoAccessExtDefaultImpl'
        constraint = 'noConstraintImpl'
        defaultpolicy_data = {'authInfoAccessCritical': 'false', 'authInfoAccessNumADs': '1', 'authInfoAccessADMethod_0': '1.3.6.1.5.5.7.48.1', 'authInfoAccessADLocationType_0': 'URIName', 'authInfoAccessADEnable_0': 'false'}
        constraintpolicy_data = {}

    elif profile_set == 'set1:p9':
        policy = 'keyUsageExtDefaultImpl'
        constraint = 'keyUsageExtConstraintImpl'
        defaultpolicy_data = {'keyUsageCritical': 'true', 'keyUsageDigitalSignature': 'true', 'keyUsageNonRepudiation': 'true', 'keyUsageKeyEncipherment': 'true', 'keyUsageKeyCertSign': 'false', 'keyUsageDataEncipherment': 'false', 'keyUsageKeyAgreement': 'false', 'keyUsageCrlSign': 'false', 'keyUsageEncipherOnly': 'false', 'keyUsageDecipherOnly': 'false'}
        constraintpolicy_data = {'keyUsageCritical': 'true', 'keyUsageDigitalSignature': 'true', 'keyUsageNonRepudiation': 'true', 'keyUsageKeyEncipherment': 'true', 'keyUsageDataEncipherment': 'false', 'keyUsageKeyAgreement': 'false', 'keyUsageKeyCertSign': 'false', 'keyUsageCrlSign': 'false', 'keyUsageEncipherOnly': 'false', 'keyUsageDecipherOnly': 'false'}

    elif profile_set == 'set1:p10':
        policy = 'signingAlgDefaultImpl'
        constraint = 'signingAlgConstraintImpl'
        defaultpolicy_data = {'signingAlg': 'SHA256withRSA'}
        constraintpolicy_data = {'signingAlgsAllowed': 'SHA1withRSA,MD5withRSA,MD2withRSA,SHA1withDSA,SHA256withRSA,SHA512withRSA,SHA1withEC,SHA256withEC,SHA384withEC,SHA512withEC'}

    req_data = {
        'OP_TYPE': 'OP_ADD',
        'OP_SCOPE': 'policies',
        'RS_ID': '{};{};{};{}'.format(profile, profile_set, policy, constraint)
    }
    response = requests.post(ca_url + '/ca/caprofile', data=req_data, verify=False, auth=(valid_admin_user, constants.CA_PASSWORD))
    if response.status_code == 200:
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()

    req_data = {
        'OP_TYPE': 'OP_ADD',
        'OP_SCOPE': 'defaultPolicy',
        'RS_ID': '{};{};{};{}'.format(profile, profile_set, policy, constraint)
    }
    req_data.update(defaultpolicy_data)
    response = requests.post(ca_url + '/ca/caprofile', data=req_data, verify=False, auth=(valid_admin_user, constants.CA_PASSWORD))
    if response.status_code == 200:
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()

    req_data = {
        'OP_TYPE': 'OP_ADD',
        'OP_SCOPE': 'constraintPolicy',
        'RS_ID': '{};{};{};{}'.format(profile, profile_set, policy, constraint)
    }
    req_data.update(constraintpolicy_data)
    response = requests.post(ca_url + '/ca/caprofile', data=req_data, verify=False, auth=(valid_admin_user, constants.CA_PASSWORD))
    if response.status_code == 200:
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()

    req_data = {
        'OP_TYPE': 'OP_READ',
        'OP_SCOPE': 'policies',
        'RS_ID': profile
    }
    response = requests.post(ca_url + '/ca/caprofile', data=req_data, verify=False, auth=(valid_admin_user, constants.CA_PASSWORD))
    if response.status_code == 200:
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()


def test_ca_ag_enroll_user_cert(ansible_module):
    """
    :id: 6934e92f-56d6-4341-9352-7713ad218208
    :Title: Enroll a user certificate with newly created profile
    :Description: Enroll a user certificate with newly created profile
    :Requirement: RHCS-REQ Certificate Authority Agent Services
    :CaseComponent: \-
    :Setup:
        1. Use the subsystems setup in ansible to run subsystem commands
        2. Use the CA setup certificate files to run CA Agent APIs
    :Steps:
         1. Enable newly created profile
         2. Create a Cert Request using python request module
         3. Check Request Status and request profile details
         4. Check Request and approve
    :ExpectedResults:
        1.Profile should be enabled successfully
        2.Certificate Request should raised successfully
        3.Certificate Request should have correct profile details
        4.Certificate Request should be approved successfully
    """
    out = ansible_module.shell('pki -p {} -d {} -c {} -n {} ca-profile-enable {}'.format(constants.CA_HTTPS_PORT, constants.NSSDB, constants.CLIENT_DATABASE_PASSWORD, valid_agent_user, profile))
    for result in out.values():
        if result['rc'] == 0:
            log.info("Successfully enabled profile: {}".format(profile))
        else:
            pytest.fail("Failed to run: {}".format("".join(result['cmd'])))

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
        'profileId': profile,
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

    out = ansible_module.shell('pki -d {} -c {} -p {} -n {} ca-cert-show {}'.format(constants.NSSDB, constants.CLIENT_DATABASE_PASSWORD, constants.CA_HTTPS_PORT, valid_agent_user, cert_serial))
    for result in out.values():
        if result['rc'] == 0:
            assert 'VALID' in result['stdout']
            assert 'Serial Number: {}'.format(cert_serial.lower()) in result['stdout']
        else:
            pytest.fail("Failed to run: {}".format("".join(result['cmd'])))


def test_ca_ag_disable_profile_admin_cert(ansible_module):
    """
    :id: 9088b3de-297b-44b1-9f9e-c7046aa41f2f
    :Title: CA - Verify Disabling the profile with Admin only cert fails
    :Description: CA - Verify Disabling the profile with Admin only cert fails
    :Requirement: RHCS-REQ Certificate Authority Agent Services
    :CaseComponent: \-
    :Setup:
        1. Use the subsystems setup in ansible to run subsystem commands
        2. Use the CA setup certificate files to run CA Agent APIs
    :Steps:
        1. Using admin cert, disable the profile
        2. Using agent cert, enable the profile
    :ExpectedResults:
        1.Profile disable should fail with admin cert
        2.Profile enable should fail with agent cert as already enabled
    """
    req_data = {
        'profileId': profile,
        'Disable': 'Disable'
    }
    response = requests.post(ca_url + "/ca/agent/ca/profileApprove", data=req_data, verify='/tmp/rootca.pem', cert=valid_admin_cert)
    if response.status_code == 200:
        assert 'errorReason="Authorization Error"' in response.content
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()

    out = ansible_module.shell('pki -p {} -d {} -c {} -n {} ca-profile-enable {}'.format(constants.CA_HTTPS_PORT, constants.NSSDB, constants.CLIENT_DATABASE_PASSWORD, valid_agent_user, profile))
    for result in out.values():
        if result['rc'] == 255:
            assert 'Profile already enabled' in result['stderr']
        else:
            pytest.fail("Failed to run: {}".format("".join(result['cmd'])))


def test_ca_ag_enable_profile_admin_cert(ansible_module):
    """
    :id: 4e072079-9e12-4fbe-8367-9997b06d4e13
    :Title: CA - Verify Enabling the profile with Admin only cert fails
    :Description: CA - Verify Enabling the profile with Admin only cert fails
    :Requirement: RHCS-REQ Certificate Authority Agent Services
    :CaseComponent: \-
    :Setup: Use the CA setup certificate files to run CA Agent APIs
    :Steps:
        1. Using agent cert, disable the profile
        2. Using admin cert, enable the profile
    :ExpectedResults:
        1.Profile disable should pass with agent cert
        2.Profile enable should fail with admin cert
    """
    req_data = {
        'profileId': profile,
        'Disable': 'Disable'
    }
    response = requests.post(ca_url + "/ca/agent/ca/profileApprove", data=req_data, verify='/tmp/rootca.pem', cert=valid_agent_cert)
    if response.status_code == 200:
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()

    req_data = {
        'profileId': profile,
        'Approve': 'Approve'
    }
    response = requests.post(ca_url + "/ca/agent/ca/profileApprove", data=req_data, verify='/tmp/rootca.pem', cert=valid_admin_cert)
    if response.status_code == 200:
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()

    out = ansible_module.shell('pki -p {} -d {} -c {} -n {} ca-profile-disable {}'.format(constants.CA_HTTPS_PORT, constants.NSSDB, constants.CLIENT_DATABASE_PASSWORD, valid_agent_user, profile))
    for result in out.values():
        if result['rc'] == 255:
            assert 'Profile already disabled' in result['stderr']
        else:
            pytest.fail("Failed to run: {}".format("".join(result['cmd'])))


def test_ca_ag_disable_profile_audit_cert(ansible_module):
    """
    :id: 4d039c0e-2adb-4173-90dd-2e3fd8f3f884
    :Title: CA - Verify Enabling the profile with Admin only cert fails
    :Description: CA - Verify Enabling the profile with Admin only cert fails
    :Requirement: RHCS-REQ Certificate Authority Agent Services
    :CaseComponent: \-
    :Setup:
        1. Use the subsystems setup in ansible to run subsystem commands
        2. Use the CA setup certificate files to run CA Agent APIs
    :Steps:
        1. Using agent cert, enable the profile
        2. Using audit cert, disable the profile
    :ExpectedResults:
        1.Profile enable should pass with agent cert
        2.Profile disable should fail with audit cert
    """
    out = ansible_module.shell('pki -p {} -d {} -c {} -n {} ca-profile-enable {}'.format(constants.CA_HTTPS_PORT, constants.NSSDB, constants.CLIENT_DATABASE_PASSWORD, valid_agent_user, profile))
    for result in out.values():
        if result['rc'] == 0:
            log.info("Successfully run command for profile enable")
        else:
            pytest.fail("Failed to run: {}".format("".join(result['cmd'])))

    req_data = {
        'profileId': profile,
        'Disable': 'Disable'
    }
    response = requests.post(ca_url + "/ca/agent/ca/profileApprove", data=req_data, verify='/tmp/rootca.pem', cert=valid_audit_cert)
    if response.status_code == 200:
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()

    out = ansible_module.shell('pki -p {} -d {} -c {} -n {} ca-profile-enable {}'.format(constants.CA_HTTPS_PORT, constants.NSSDB, constants.CLIENT_DATABASE_PASSWORD, valid_agent_user, profile))
    for result in out.values():
        if result['rc'] == 255:
            assert 'Profile already enabled' in result['stderr']
        else:
            pytest.fail("Failed to run: {}".format("".join(result['cmd'])))


def test_ca_ag_enable_profile_audit_cert(ansible_module):
    """
    :id: 9fce4d4d-dd2c-4504-b97f-ad800289cbf2
    :Title: CA - Verify Enabling the profile with Admin only cert fails
    :Description: CA - Verify Enabling the profile with Admin only cert fails
    :Requirement: RHCS-REQ Certificate Authority Agent Services
    :CaseComponent: \-
    :Setup:
        1. Use the subsystems setup in ansible to run subsystem commands
        2. Use the CA setup certificate files to run CA Agent APIs
    :Steps:
        1. Using agent cert, disable the profile
        2. Using audit cert, enable the profile
    :ExpectedResults:
        1.Profile disable should pass with agent cert
        2.Profile enable should fail with audit cert
    """

    out = ansible_module.shell('pki -p {} -d {} -c {} -n {} ca-profile-disable {}'.format(constants.CA_HTTPS_PORT, constants.NSSDB, constants.CLIENT_DATABASE_PASSWORD, valid_agent_user, profile))
    for result in out.values():
        if result['rc'] == 0:
            log.info("Successfully run command for profile disable")
        else:
            pytest.fail("Failed to run: {}".format("".join(result['cmd'])))

    req_data = {
        'profileId': profile,
        'Approve': 'Approve'
    }
    response = requests.post(ca_url + "/ca/agent/ca/profileApprove", data=req_data, verify='/tmp/rootca.pem', cert=valid_audit_cert)
    if response.status_code == 200:
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()

    out = ansible_module.shell('pki -p {} -d {} -c {} -n {} ca-profile-disable {}'.format(constants.CA_HTTPS_PORT, constants.NSSDB, constants.CLIENT_DATABASE_PASSWORD, valid_agent_user, profile))
    for result in out.values():
        if result['rc'] == 255:
            assert 'Profile already disabled' in result['stderr']
        else:
            pytest.fail("Failed to run: {}".format("".join(result['cmd'])))
