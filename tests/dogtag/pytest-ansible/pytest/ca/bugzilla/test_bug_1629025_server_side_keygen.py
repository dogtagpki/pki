#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Bugzilla Automation 1629025 Server Side KeyGen
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Deepak Punia <dpunia@redhat.com>
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

import datetime, time
import logging
import os
import re
import sys
import pytest
import requests

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

TOPOLOGY = constants.CA_INSTANCE_NAME.split("-")[-2]

if TOPOLOGY == '01':
    ca_instance = "pki-tomcat"
    kra_instance = "pki-tomcat"
else:
    ca_instance = constants.CA_INSTANCE_NAME
    kra_instance = constants.KRA_INSTANCE_NAME

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)

ca_url = 'https://{}:{}'.format(constants.MASTER_HOSTNAME, constants.CA_HTTPS_PORT)
BASE_DIR = '/var/lib/pki/'
transport_nick = "transportCert cert-{} KRA".format(kra_instance)
ca_cfg_path = BASE_DIR + '/' + ca_instance + '/' + 'ca/conf/CS.cfg'
profile = ['caServerKeygen_UserCert', 'caServerKeygen_DirUserCert']


def test_setup(ansible_module):
    ansible_module.lineinfile(path=ca_cfg_path, regexp="ca.enableNonces=true", line="ca.enableNonces=false")

    # importing KRA certificate into CA nssdb.
    ansible_module.shell('certutil -L -d {}{}/alias -n "{}" -a > '
                         '/tmp/kra.cert'.format(BASE_DIR, kra_instance, transport_nick))
    ansible_module.lineinfile(path=ca_cfg_path, line="ca.connector.KRA.transportCertNickname={}".format(transport_nick))

    ansible_module.shell("grep -i 'internal=' /etc/pki/%s/password.conf | awk -F'=' ' { print $2 } ' >/tmp/pass" % (ca_instance))
    ansible_module.shell('certutil -A -d {}{}/alias -n "{}" -t "CT,C,C" -i /tmp/kra.cert -f /tmp/pass'.format(BASE_DIR, ca_instance,
                                                                                             transport_nick))

    ansible_module.command('pki-server restart {}'.format(ca_instance))
    time.sleep(5)
    log.info("Restarted instance : {}".format(ca_instance))

    ansible_module.shell("openssl pkcs12 -in /opt/{}/ca_admin_cert.p12 "
                         "-out /tmp/auth_cert.pem -nodes -passin pass:{}".format(constants.CA_INSTANCE_NAME,
                                                                                 constants.CLIENT_DATABASE_PASSWORD))
    ansible_module.fetch(src="/tmp/auth_cert.pem", dest="/tmp/auth_cert.pem", flat="yes")
    if TOPOLOGY == '01':
        ansible_module.fetch(src='{}{}/alias/ca.crt'.format(BASE_DIR,ca_instance), dest='/tmp/rootCA.pem', flat="yes")
    else:
        ansible_module.fetch(src='/tmp/rootCA.pem', dest='/tmp/rootCA.pem', flat="yes")


@pytest.mark.parametrize("keytype,keysize", [("RSA", ["1024"]), ("RSA", ["2048"]), ("RSA", ["3072"]), ("RSA", ["4096"]),
                                             ("EC", ["nistp256"]), ("EC", ["nistp384"]), ("EC", ["nistp521"])])
def test_manual_cert_enroll_with_server_side_keygen(keytype, keysize):
    """
    :id: 0d42818e-5de6-4197-97c1-4ba60bc7bec2
    :Title: Enrolling Certificate Using Server-Side Keygen
    :Description: Enrolling Certificate Using Server-Side Keygen using both RSA and ECC
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Generate certificate through EE page using profile
            "Manual User Dual-Use Certificate Enrollment using server-side Key generation"
        2. Approve the request
    :ExpectedResults:
        1. Certificate Request should raised succesfully.
        2. Should able to approve request.
    """
    user_id = "user_{}_{}".format(keytype, keysize)
    # Create Certificate Request with Requests Module
    cert_request_data = {
        'serverSideKeygenP12Passwd': constants.CLIENT_PKCS12_PASSWORD,
        'p12PasswordAgain': constants.CLIENT_PKCS12_PASSWORD,
        'keyType': keytype,
        'keySize': keysize,
        'sn_uid': user_id,
        'profileId': profile[0],
        'renewal': 'false',
        'xmlOutput': 'false'
    }
    response = requests.post(ca_url + "/ca/ee/ca/profileSubmit", data=cert_request_data,
                             verify='/tmp/rootCA.pem', cert='/tmp/auth_cert.pem')

    if response.status_code == 200:
        request = re.findall('requestList.requestId="[\w]*"', response.content)
        request_id = request[0].split("=")[1].strip().replace("\"", "")
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()

    # Approve Above Request
    req_approval_data = {
        'requestId': '{}'.format(request_id),
        'op': 'approve',
        'submit': 'submit',
        'name': 'UID={}'.format(user_id),
        'notBefore': datetime.date.today().strftime("%Y-%m-%d %H:%M:%S"),
        'notAfter': (datetime.date.today() + datetime.timedelta(days=365)).strftime("%Y-%m-%d %H:%M:%S"),
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
    response = requests.post(ca_url + "/ca/agent/ca/profileProcess",
                             data=req_approval_data, verify='/tmp/rootCA.pem', cert="/tmp/auth_cert.pem")
    if response.status_code == 200:
        assert 'CA Signing Certificate' in response.content
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()


def test_dir_auth_setup(ansible_module):
    # Adding UserDirEnrollment to authenticate through LDAP user
    DirEnrollment_paramter = """auths.instance.UserDirEnrollment.ldap.basedn={}
auths.instance.UserDirEnrollment.ldap.ldapconn.host={}
auths.instance.UserDirEnrollment.ldap.ldapconn.port={}
auths.instance.UserDirEnrollment.ldap.ldapconn.secureConn=false
auths.instance.UserDirEnrollment.ldapStringAttributes=mail
auths.instance.UserDirEnrollment.pluginName=UidPwdDirAuth
""".format(constants.LDAP_BASE_DN, constants.MASTER_HOSTNAME, constants.LDAP_PORT)

    ansible_module.lineinfile(path=ca_cfg_path, line=DirEnrollment_paramter)
    ansible_module.command('pki-server restart {}'.format(ca_instance))
    time.sleep(5)

    # Creating ldap user
    ansible_module.replace(dest="/tmp/test_dir/ldap_user_add.cfg", regexp="LDAP_USER", replace=constants.LDAP_USER1)
    ansible_module.replace(dest="/tmp/test_dir/ldap_user_add.cfg", regexp="LDAP_PASSWD", replace=constants.LDAP_PASSWD)
    ldap_user_out = ansible_module.shell('ldapadd -h {} -p {} -D "cn=Directory Manager" -w {} -f '
                                         '"/tmp/test_dir/ldap_user_add.cfg"'.format(constants.MASTER_HOSTNAME,
                                                                                    constants.LDAP_PORT,
                                                                                    constants.LDAP_PASSWD))
    for result in ldap_user_out.values():
        if result['rc'] == 0:
            assert "adding new entry" in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            log.info("Failed to run : '{}'".format(result['cmd']))
            pytest.fail()


@pytest.mark.parametrize("keytype,keysize", [("RSA", ["1024"]), ("RSA", ["2048"]), ("RSA", ["3072"]), ("RSA", ["4096"]),
                                             ("EC", ["nistp256"]), ("EC", ["nistp384"]), ("EC", ["nistp521"])])
def test_dir_auth_cert_enroll_with_server_side_keygen(ansible_module, keytype, keysize):
    """
    :id: 89358a83-9152-450c-b250-7c4a95a30669
    :Title: Directory-authenticated : Enrolling Certificate Using Server-Side Keygen on shared-Tomcat RSA
    :Description: Directory-authenticated : Enrolling Certificate Using Server-Side Keygen using both RSA and ECC
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Generate certificate through EE page using profile
            "Directory-authenticated User Dual-Use Certificate Enrollment using server-side Key generation"
        2. Approve the request
    :ExpectedResults:
        1. Certificate Request should raised succesfully.
        2. Should able to approve request.
    """
    user_id = "user_{}_{}".format(keytype, keysize)
    # Create Certificate Request with Requests Module
    cert_request_data = {
        'uid': constants.LDAP_USER1,
        'pwd': constants.CLIENT_DIR_PASSWORD,
        'serverSideKeygenP12Passwd': constants.CLIENT_PKCS12_PASSWORD,
        'p12PasswordAgain': constants.CLIENT_PKCS12_PASSWORD,
        'keyType': keytype,
        'keySize': keysize,
        'sn_uid': user_id,
        'profileId': profile[1],
        'renewal': 'false',
        'xmlOutput': 'false'
    }
    response = requests.post(ca_url + "/ca/ee/ca/profileSubmit", data=cert_request_data,
                             verify='/tmp/rootCA.pem', cert='/tmp/auth_cert.pem')

    if response.status_code == 200:
        assert 'CA Signing Certificate' in response.content
        log.info("Successfully run: {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()


def test_remove_setup(ansible_module):
    ansible_module.shell('rm -rf /tmp/kra.cert /tmp/pass /tmp/auth_cert.pem ')
