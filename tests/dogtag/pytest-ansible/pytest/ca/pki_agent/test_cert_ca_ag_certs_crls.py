#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description:  PKI CA Agent Certificates and CRL tests
#                 Bugzilla Automation 1854043 PrettyPrintCert is failing
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
import re
import pytest
import requests
import sys
import os
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
valid_admin_user = 'CA_AdminV'
valid_agent_cert = '/tmp/{}.pem'.format(valid_agent_user)
user_num = random.randint(1111111, 9999999)
testcrl = "testcrl{}".format(user_num)


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
        3. Change admin user password
    :Expected Results:
       1. Nonces property is disabled
       2. Valid Agent and CA Signing certificate pem files are created to be used in request module
       3. Password for admin user changed successfully
    """
    ansible_module.lineinfile(path=ca_cfg_path, regexp="ca.enableNonces=true", line="ca.enableNonces=false")
    restart_instance(ansible_module)
    log.info("Restarted instance : {}".format(instance))

    ansible_module.shell('pki -d {} -c {} pkcs12-cert-import {} --pkcs12-file /tmp/{}.p12 --pkcs12-password {}'.format(constants.NSSDB, constants.CLIENT_DATABASE_PASSWORD, valid_agent_user, valid_agent_user, constants.CLIENT_DATABASE_PASSWORD))
    ansible_module.shell("openssl pkcs12 -in /tmp/{}.p12 -out {} -nodes -passin pass:{}".format(valid_agent_user, valid_agent_cert, constants.CLIENT_DATABASE_PASSWORD))
    ansible_module.shell('certutil -L -d {} -n "caSigningCert cert-{} CA" -a > /tmp/rootca.pem'.format(BASE_DIR + instance + "/alias", instance))
    ansible_module.fetch(src=valid_agent_cert, dest=valid_agent_cert, flat="yes")
    ansible_module.fetch(src='/tmp/rootca.pem', dest='/tmp/rootca.pem', flat="yes")

    out = ansible_module.shell('pki -p {} -d {} -c {} -n "{}" ca-user-mod {} --password {}'.format(constants.CA_HTTPS_PORT, constants.NSSDB, constants.CLIENT_DATABASE_PASSWORD, constants.CA_ADMIN_NICK, valid_admin_user, constants.CLIENT_DATABASE_PASSWORD))

    for result in out.values():
        if result['rc'] == 0:
            log.info("Successfully modified admin user password")
        else:
            pytest.fail("Failed to run: {}".format("".join(result['cmd'])))


def test_check_prettyprintcert_output(ansible_module):
    """
    :id: b1da6f87-5827-4ef6-a7ac-2d6f47e7a96b
    :Title: Bugzilla Automation 1854043 PrettyPrintCert is failing
    :Description: Bugzilla Automation 1854043 PrettyPrintCert is failing
    :Requirement: RHCS-REQ Certificate Authority Agent Services
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Check cert file has single certificate, not chain of certificates
        2. Run PrettyPrintCert on Certificate file
    :ExpectedResults:
        1.PrettyPrintCert command must display the contents of a certificate in readable format
    """
    out = ansible_module.shell('grep "BEGIN CERTIFICATE" /tmp/rootca.pem | wc -l')
    assert '1' in out.values()[0]['stdout']

    res = ansible_module.shell('/usr/bin/PrettyPrintCert /tmp/rootca.pem')
    for result in res.values():
        if result['rc'] == 0:
            assert 'Serial Number: ' in result['stdout']
            assert 'Subject: ' in result['stdout']
            assert 'Signature: ' in result['stdout']
        else:
            pytest.fail("Failed to run: {}".format("".join(result['cmd'])))


def test_ca_ag_list_certs():
    """
    :id: c4b88c96-53e6-49d1-bffb-1235ea73fac5
    :Title: CA Agent Page: List Certificates
    :Description: CA Agent Page: List Certificates
    :Requirement: RHCS-REQ Certificate Authority Agent Services
    :CaseComponent: \-
    :Setup: Use the CA setup certificate files to run CA Agent APIs
    :Steps:
        1. Create a Cert Request using python request module
        2. Check Request Status and approve
        3. Check and list certificates
    :ExpectedResults:
        1.Certificate Request should raised successfully
        2.Certificate details should displayed successfully
    """

    req_data = {
        'crlIssuingPoint': 'MasterCRL',
        'waitForUpdate': 'true',
        'clearCRLCache': 'true',
        'cancelCurCustomFutureThisUpdateValue': 'true'
    }
    response = requests.post(ca_url + "/ca/agent/ca/updateCRL", data=req_data, verify='/tmp/rootca.pem', cert=valid_agent_cert)
    if response.status_code == 200:
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()

    req_data = {
        'op': 'listCerts',
        'queryCertFilter': '(|(certStatus=VALID)(certStatus=REVOKED))',
        'querySentinelDown': '0',
        'direction': '',
        'maxCount': '20'
    }
    response = requests.post(ca_url + "/ca/agent/ca/listCerts", data=req_data, verify='/tmp/rootca.pem', cert=valid_agent_cert)
    if response.status_code == 200:
        assert response.content.count("record.subject=") == 20
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()


def test_ca_ag_revoke_certs(ansible_module):
    """
    :id: eaaf87b5-8f9b-4a09-a8b6-4a490597dba6
    :Title: CA Agent Page: Revoke Certificates
    :Description: CA Agent Page: Revoke Certificates
    :Requirement: RHCS-REQ Certificate Authority Agent Services
    :CaseComponent: \-
    :Setup:
        1. Use the subsystems setup in ansible to run subsystem commands
        2. Use the CA setup certificate files to run CA Agent APIs
    :Steps:
        1. Create a Cert Request using python request module
        2. Check Request Status and approve
        3. Check certificate and revoke it
    :ExpectedResults:
        1.Certificate Request should raised successfully
        2.Certificate details should displayed successfully
        3.Certificate should be revoked successfully
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
        cert_decimal = int(cert_serial, 16)
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()

    req_data = {
        'op': 'doRevoke',
        'revocationReason': '0',
        'revokeAll': '(certRecordID={})'.format(cert_decimal),
        'submit': 'Submit',
    }
    response = requests.post(ca_url + "/ca/agent/ca/doRevoke", data=req_data, verify='/tmp/rootca.pem', cert=valid_agent_cert)
    if response.status_code == 200:
        assert 'header.revoked = "yes"' in response.content
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()


@pytest.mark.parametrize('crl_type', ['cachedCRL', 'entireCRL', 'crlHeader', 'base64Encoded'])
def test_ca_ag_display_crl(crl_type):
    """
    :id: 3824e090-6a54-4def-8497-5cc4cead644c
    :parametrized: yes
    :Title: CA Agent Page: Display Revocation List
    :Description: CA Agent Page: Display Revocation List
    :Requirement: RHCS-REQ Certificate Authority Agent Services
    :CaseComponent: \-
    :Setup: Use the CA setup certificate files to run CA Agent APIs
    :Steps:
        1. Display the Certificate revoke list
    :ExpectedResults:
        1.CRL should be displayed successfully
    """
    req_data = {
        'crlIssuingPoint': 'MasterCRL',
        'crlDisplayType': crl_type,
        'pageStart': '1',
        'pageSize': '50'
    }
    response = requests.post(ca_url + "/ca/agent/ca/displayCRL", data=req_data, verify='/tmp/rootca.pem', cert=valid_agent_cert)
    if response.status_code == 200:
        assert 'header.crlDisplayType = "{}"'.format(crl_type) in response.content
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()


def test_ca_ag_update_master_crl():
    """
    :id: 157c4391-478f-4196-8da3-0baf98d92a06
    :Title: CA Agent Page: Update Revocation List
    :Description: CA Agent Page: Update Revocation List
    :Requirement: RHCS-REQ Certificate Authority Agent Services
    :CaseComponent: \-
    :Setup: Use the CA setup certificate files to run CA Agent APIs
    :Steps:
        1. Update the Certificate revoke list
    :ExpectedResults:
        1.CRL should be updated successfully
    """
    req_data = {
        'crlIssuingPoint': 'MasterCRL',
        'signatureAlgorithm': 'SHA512withRSA',
        'pageStart': '1',
        'pageSize': '50'
    }
    response = requests.post(ca_url + "/ca/agent/ca/updateCRL", data=req_data, verify='/tmp/rootca.pem', cert=valid_agent_cert)

    if response.status_code == 200:
        assert 'header.crlIssuingPoint = "MasterCRL"' in response.content
        assert 'header.crlUpdate = "Scheduled"' in response.content
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()


def test_ca_ag_display_master_crl():
    """
    :id: 215bd171-13fd-4749-b2a1-8b85730da51e
    :Title: CA - Agent Interface - Display Master CRL with entire CRL display type
    :Description: CA - Agent Interface - Display Master CRL with entire CRL display type
    :Requirement: RHCS-REQ Certificate Authority Agent Services
    :CaseComponent: \-
    :Setup: Use the CA setup certificate files to run CA Agent APIs
    :Steps:
        1. Display Master CRL with entire CRL display type
    :ExpectedResults:
        1.Master CRL with entire CRL display type should be displayed successfully
    """
    req_data = {
        'crlIssuingPoint': 'MasterCRL',
        'crlDisplayType': 'entireCRL',
        'pageStart': '1',
        'pageSize': '50'
    }
    response = requests.post(ca_url + "/ca/agent/ca/displayCRL", data=req_data, verify='/tmp/rootca.pem', cert=valid_agent_cert)

    if response.status_code == 200:
        assert 'header.crlIssuingPoint = "MasterCRL"' in response.content
        assert 'Signature:' in response.content
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()


def test_ca_ag_add_testcrl():
    """
    :id: 1346d5e7-bb41-4280-b342-e337e4f04800
    :Title: CA - Agent Interface - Add Test CRL
    :Description: CA - Agent Interface - Add Test CRL
    :Requirement: RHCS-REQ Certificate Authority Agent Services
    :CaseComponent: \-
    :Setup: Use the CA setup certificate files to run CA Agent APIs
    :Steps:
        1. Add Test CRL
    :ExpectedResults:
        1.Test CRL should be added successfully
    """
    req_data = {
        'OP_TYPE': 'OP_ADD',
        'OP_SCOPE': 'crlIPs',
        'RS_ID': testcrl,
        'id': testcrl,
        'description': testcrl,
        'enable': 'true'
    }
    response = requests.post(ca_url + '/ca/caadmin', data=req_data, verify=False, auth=(valid_admin_user, constants.CA_PASSWORD))
    if response.status_code == 200:
        assert 'id={}'.format(testcrl) in response.content
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()


@pytest.mark.parametrize('crl', ['cachedCRL', 'crlHeader', 'base64Encoded'])
def test_ca_ag_display_testcrl(crl):
    """
    :id: 1e6a93fe-5f49-4ff3-ae9f-51f6c66da529
    :parametrized: yes
    :Title: CA - Agent Interface - Display a newly added CRL with CRL display type
    :Description: CA - Agent Interface - Display Master CRL with CRL display type
    :Requirement: RHCS-REQ Certificate Authority Agent Services
    :CaseComponent: \-
    :Setup: Use the CA setup certificate files to run CA Agent APIs
    :Steps:
        1. Display CRL display types
    :ExpectedResults:
        1.Master CRL should be displayed successfully
    """
    req_data = {
        'crlIssuingPoint': testcrl,
        'crlDisplayType': crl,
        'pageStart': '1',
        'pageSize': '50'
    }
    response = requests.post(ca_url + "/ca/agent/ca/displayCRL", data=req_data, verify='/tmp/rootca.pem', cert=valid_agent_cert)

    if response.status_code == 200:
        if crl == 'base64Encoded':
            assert 'header.crlIssuingPoint = "{}"'.format(testcrl) in response.content
            assert 'BEGIN CERTIFICATE REVOCATION LIST' in response.content
        else:
            assert 'header.crlIssuingPoint = "{}"'.format(testcrl) in response.content
            assert 'Signature Algorithm:' in response.content
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()

    req_data = {
        'crlIssuingPoint': testcrl,
        'crlDisplayType': 'cachedCRL',
        'pageStart': '1',
        'pageSize': '50'
    }
    response = requests.post(ca_url + "/ca/agent/ca/displayCRL", data=req_data, verify='/tmp/rootca.pem', cert=valid_agent_cert)
    if response.status_code == 200:
        assert 'header.crlIssuingPoint = "{}"'.format(testcrl) in response.content
        assert 'Issuer:' in response.content
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()


def display_crl(crl_number):
    """
    Function to display CRL as per crl number
    """
    req_data = {
        'crlIssuingPoint': testcrl,
        'crlDisplayType': 'entireCRL',
        'pageStart': '1',
        'pageSize': '50'
    }
    response = requests.post(ca_url + "/ca/agent/ca/displayCRL", data=req_data,
                             verify='/tmp/rootca.pem', cert=valid_agent_cert)
    if response.status_code == 200:
        assert 'header.crlNumber = "{}"'.format(crl_number) in response.content
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))


def test_ca_ag_update_testcrl():
    """
    :id: a4282313-0fc3-49b0-b805-1173b6326c58
    :Title: CA Agent Page: Update Test Revocation List
    :Description: CA Agent Page: Update Test Revocation List
    :Requirement: RHCS-REQ Certificate Authority Agent Services
    :CaseComponent: \-
    :Setup: Use the CA setup certificate files to run CA Agent APIs
    :Steps:
        1. Update the test Certificate revoke list
    :ExpectedResults:
        1. Test CRL should be updated successfully
    """

    display_crl(1)

    # Update CRL
    req_data = {
        'crlIssuingPoint': testcrl,
        'waitForUpdate': 'true',
        'signatureAlgorithm': 'SHA256withRSA',
        'pageStart': '1',
        'pageSize': '50'
    }
    response = requests.post(ca_url + "/ca/agent/ca/updateCRL", data=req_data, verify='/tmp/rootca.pem', cert=valid_agent_cert)
    if response.status_code == 200:
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()

    display_crl(2)

    # Delete CRL
    req_data = {
        'OP_TYPE': 'OP_DELETE',
        'OP_SCOPE': 'crlIPs',
        'LdapCrlMapD': testcrl,
    }
    response = requests.post(ca_url + '/ca/caadmin', data=req_data, verify=False, auth=(valid_admin_user, constants.CA_PASSWORD))
    if response.status_code == 200:
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()


def test_ca_ag_update_ds():
    """
    :id: d3e40cf8-a919-4140-b4f6-0d8a8f5ecc4c
    :Title: CA - Agent Interface - Update DS
    :Description: CA - Agent Interface - Update DS
    :Requirement: RHCS-REQ Certificate Authority Agent Services
    :CaseComponent: \-
    :Setup: Use the CA setup certificate files to run CA Agent APIs
    :Steps:
        1. Update the Directory Server
    :ExpectedResults:
        1. Directory Server should be updated successfully
    """
    user_num1 = random.randint(1111111, 9999999)
    testcrl1 = "testcrl1{}".format(user_num1)
    dn_pattern = 'UID={},OU=people,O={}'.format(testcrl1, constants.CA_INSTANCE_NAME)

    # Edit LDAP ca cert mapper
    req_data = {
        'OP_TYPE': 'OP_MODIFY',
        'OP_SCOPE': 'mapperRules',
        'RULENAME': 'LdapCaCertMap',
        'createCAEntry': 'true',
        'implName': 'LdapCaSimpleMap',
        'RD_ID': 'LdapCaCertMap',
        'RS_ID': testcrl1,
        'dnPattern': dn_pattern
    }
    response = requests.post(ca_url + '/ca/capublisher', data=req_data, verify=False, auth=(valid_admin_user, constants.CA_PASSWORD))
    if response.status_code == 200:
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()
    # Edit LDAP user cert mapper
    req_data = {
        'OP_TYPE': 'OP_MODIFY',
        'OP_SCOPE': 'mapperRules',
        'RULENAME': 'LdapUserCertMap',
        'implName': 'LdapSimpleMap',
        'RD_ID': 'LdapUserCertMap',
        'RS_ID': testcrl1,
        'dnPattern': dn_pattern
    }
    response = requests.post(ca_url + '/ca/capublisher', data=req_data, verify=False, auth=(valid_admin_user, constants.CA_PASSWORD))
    if response.status_code == 200:
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()

    # Edit LDAP crl mapper
    req_data = {
        'OP_TYPE': 'OP_MODIFY',
        'OP_SCOPE': 'mapperRules',
        'RULENAME': 'LdapCrlMap',
        'createCAEntry': 'true',
        'implName': 'LdapCaSimpleMap',
        'RD_ID': 'LdapCrlMap',
        'RS_ID': testcrl1,
        'dnPattern': dn_pattern
    }
    response = requests.post(ca_url + '/ca/capublisher', data=req_data, verify=False, auth=(valid_admin_user, constants.CA_PASSWORD))
    if response.status_code == 200:
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()

    def test_ldap_auth_config(op_type):
        req_ldap_data = {
            'OP_TYPE': op_type,
            'OP_SCOPE': 'ldap',
            'RD_ID': 'RD_ID_CONFIG',
            'publishingEnable': 'true',
            'enable': 'true',
            'ldapconn.host': constants.MASTER_HOSTNAME,
            'ldapconn.port': constants.LDAP_PORT,
            'ldapconn.secureConn': 'false',
            'ldapauth.bindPWPrompt': 'CA LDAP Publishing',
            'ldapauth.bindDN': constants.LDAP_BIND_DN,
            'directoryManagerPwd': 'SECret.123',
            'ldapconn.version': '3',
            'ldapauth.authtype': 'BasicAuth',
            'ldapauth.clientCertNickname': '',
        }
        res = requests.post(ca_url + '/ca/capublisher', data=req_ldap_data, verify=False,
                                 auth=(valid_admin_user, constants.CA_PASSWORD))
        if res.status_code == 200:
            log.info("Successfully run: {}".format(res.status_code))
        else:
            log.error("Failed to run : {}".format(res.status_code))
            pytest.fail()

    # Enable Publishing with Basic Auth
    test_ldap_auth_config('OP_PROCESS')
    # Save LDAP auth config
    test_ldap_auth_config('OP_MODIFY')


def test_ca_ag_revoke_cert_display_crl(ansible_module):
    """
    :id: 9f6a15c2-5230-4db3-b319-1cbacc11f7c5
    :Title: Revoke user cert and display CRL
    :Description: Revoke user cert and display CRL
    :Requirement: RHCS-REQ Certificate Authority Agent Services
    :CaseComponent: \-
    :Setup:
        1. Use the subsystems setup in ansible to run subsystem commands
        2. Use the CA setup certificate files to run CA Agent APIs
    :Steps:
        1. Create a Cert Request using python request module
        2. Check Request Status and profile details
        3. Check Request and perform revoke
        4. Display the CRL
    :ExpectedResults:
        1.Certificate Request should raised successfully
        2.Certificate Request should be revoked successfully
        3.CRL should display details of revoked cert
    """
    user_num2 = random.randint(1111111, 9999999)
    user_id2 = 'user{}'.format(user_num2)
    pop_cert = "/tmp/{}".format(user_id2)
    pop_out = ansible_module.shell('CRMFPopClient -d {} -p {} -a rsa -n '
                                   '"uid={}" -o {}'.format(constants.NSSDB,
                                                           constants.CLIENT_DATABASE_PASSWORD, user_id2, pop_cert))
    for result in pop_out.values():
        if result['rc'] == 0:
            ansible_module.fetch(src=pop_cert, dest=pop_cert, flat="yes")
            encoded_cert = open(pop_cert, "r").read()
        else:
            pytest.fail("Failed to run: {}".format("".join(result['cmd'])))

    req_data = {
        'selectKeyType': 'RSA',
        'request_type': 'crmf',
        'sn_uid': user_id2,
        'sn_cn': user_id2,
        'sn_email': "{}@example.com".format(user_id2),
        'requestor_name': user_id2,
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
        'name': 'UID={}'.format(user_id2),
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
        'requestNotes': 'submittingcertfor{}'.format(user_id2)
    }
    response = requests.post(ca_url + "/ca/agent/ca/profileProcess", data=req_approval_data, verify='/tmp/rootca.pem', cert=valid_agent_cert)

    if response.status_code == 200:
        cert_detail = re.findall('Serial Number: [\w]*', response.content)
        cert_serial = cert_detail[0].split(":")[1].strip().replace("\"", "")
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()

    # Display CRL
    req_data = {
        'crlIssuingPoint': 'MasterCRL',
        'crlDisplayType': 'entireCRL',
        'pageStart': '1',
        'pageSize': '50'
    }
    response = requests.post(ca_url + "/ca/agent/ca/displayCRL", data=req_data, verify='/tmp/rootca.pem', cert=valid_agent_cert)

    if response.status_code == 200:
        assert cert_serial not in response.content
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()

    out = ansible_module.shell('echo "Y" | pki -d {} -c {} -p {} -n "{}" ca-cert-revoke {} --force'.format(constants.NSSDB, constants.CLIENT_DATABASE_PASSWORD, constants.CA_HTTPS_PORT, valid_agent_user, cert_serial))
    for result in out.values():
        if result['rc'] == 0:
            assert 'Serial Number: {}'.format(cert_serial.lower()) in result['stdout']
            assert 'REVOKED' in result['stdout']
        else:
            pytest.fail("Failed to run: {}".format(" ".join(result['cmd'])))

    # Update DR
    req_data = {'updateCRL': 'yes'}
    response = requests.post(ca_url + "/ca/agent/ca/updateDir", data=req_data, verify='/tmp/rootca.pem', cert=valid_agent_cert)

    if response.status_code == 200:
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()

    # Update CRL
    req_data = {
        'crlIssuingPoint': 'MasterCRL',
        'signatureAlgorithm': 'SHA512withRSA'
    }
    response = requests.post(ca_url + "/ca/agent/ca/updateCRL", data=req_data, verify='/tmp/rootca.pem', cert=valid_agent_cert)

    if response.status_code == 200:
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()

    req_data = {
        'crlIssuingPoint': 'MasterCRL',
        'crlDisplayType': 'entireCRL',
        'pageStart': '1',
        'pageSize': '50'
    }
    response = requests.post(ca_url + "/ca/agent/ca/displayCRL", data=req_data, verify='/tmp/rootca.pem', cert=valid_agent_cert)

    if response.status_code == 200:
        assert cert_serial in response.content
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
