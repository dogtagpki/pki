#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI CA Auth plugins tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   PKI CA Auth plugin tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Amol Kahat <akahat@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2017 Red Hat, Inc. All rights reserved.
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

import datetime
import os
import random
import re
import sys
import time

import pytest
import requests

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

headers = {'Content-type': 'application/json',
           'Accept': 'text/plain'}

PLUGINS = ['raCertAuth', 'AgentCertAuth', 'SSLclientCertAuth', 'flatFileAuth', 'TokenAuth',
           'challengeAuthMgr', 'certUserDBAuthMgr', 'CMCAuth', 'sslClientCertAuthMgr',
           'passwdUserDBAuthMgr', 'SessionAuthentication', 'CMCUserSignedAuth']

TOPOLOGY = constants.CA_INSTANCE_NAME.split("-")[-2]

newly_added_plugins = []

plugin_add_log = "[AuditEvent=CONFIG_AUTH][SubjectID={}][Outcome=Success][ParamNameValPairs=" \
                 "Scope;;instance+Operation;;OP_ADD+Resource;;{}+implName;;{}] " \
                 "authentication configuration parameter(s) change"

plugin_del_log = "[AuditEvent=CONFIG_AUTH][SubjectID={}][Outcome=Success][ParamNameValPairs=" \
                 "Scope;;instance+Operation;;OP_DELETE+Resource;;{}] authentication " \
                 "configuration parameter(s) change"

ca_url = 'http://pki1.example.com:{}/ca/auths'.format(constants.CA_HTTP_PORT)

if TOPOLOGY == '01':
    instance = 'pki-tomcat'
else:
    instance = constants.CA_INSTANCE_NAME

BASE_DIR = '/var/lib/pki/'
ca_cfg_path = BASE_DIR + '/' + instance + '/' + 'ca/conf/CS.cfg'


def restart_instance(ansible_module):
    command = 'systemctl restart pki-tomcatd@{}'.format(instance)
    out = ansible_module.shell(command)
    for res in out.values():
        assert res['rc'] == 0

def test_setup(ansible_module):
    ansible_module.lineinfile(path=ca_cfg_path, regexp="debug.level=10", line="debug.level=5")
    restart_instance(ansible_module)
    time.sleep(15)

@pytest.fixture(scope='module', autouse=True)
def plugin_conf(request):
    request.addfinalizer(remove_added_plugins)


def get_log(ansible_module, subsystem='ca', audit=True, debug=False):
    date = datetime.datetime.now().strftime("%Y-%m-%d")
    s = subsystem.upper()
    if s in ['CA', 'KRA', 'OCSP', 'TKS', 'TPS']:
        if audit:
            logs = ansible_module.command('tail -n200 /var/log/pki/{}/ca/signedAudit/'
                                          'ca_audit'.format(instance))
        elif debug:
            logs = ansible_module.command('tail -n200 /var/log/pki/{}/ca/'
                                          'debug.{}.log'.format(instance, date))
        for res in logs.values():
            if res['rc'] == 0:
                return res['stdout']
            else:
                pytest.fail()



def test_pki_ca_auth_plugins_list():
    """
    :id: 06599604-bd84-42b2-bf0b-513aa3b07adc

    :Title: Test pki ca auth plugins list using REST API.

    :Test: Test pki ca auth plugins list using REST API.

    :Description: List the CA subsystem auth plugins using REST API

    :Requirement: Certificate Authority Authentication Plugins

    :CaseComponent: \-

    :Setup: Use the subsystems setup in ansible to run subsystem commands

    :Steps:
            1. Request to URI http://pki1.example.com:<unsecure_port>/ca/auths
            2. Pass the data OP_TYPE=OP_SEARCH&OP_SCOPE=instance&

    :Expectedresults:
                1. It should return the list of auth plugins
    """

    data = [('OP_TYPE', 'OP_SEARCH'),
            ('OP_SCOPE', 'instance')]

    response = requests.post(ca_url, params=data, headers=headers,
                             auth=(constants.CA_ADMIN_USERNAME, constants.CA_PASSWORD))
    response.encoding = 'utf-8'

    assert response.status_code == 200

    text = response.text.encode('utf-8').replace('%3Bvisible%3B', b'/')
    text = text.replace('%3Binvisible%3B', '/')
    if '\x00' in response.text:
        text = text.replace('\x00', '')
    text = text.split('&')
    all_plugs = [i.split("=")[0] for i in text]
    for plug in PLUGINS:
        assert plug in all_plugs


def test_pki_ca_auth_plugins_list_with_invalid_credentials():
    """
    :id: 37f569f2-eeb7-4d63-b567-7b15849858f0

    :Title: Test pki ca auth plugins list using REST API with invalid credential.

    :Test: Test pki ca auth plugins list using REST API with invalid credential.

    :Description: List the CA subsystem auth plugins using REST API with invalid credential

    :Requirement: Certificate Authority Authentication Plugins

    :CaseComponent: \-

    :Setup: Use the subsystems setup in ansible to run subsystem commands

    :Steps:
            1. Request to URI http://pki1.example.com:<unsecure_port>/ca/auths
            2. Pass the data OP_TYPE=OP_SEARCH&OP_SCOPE=instance&
    :Expectedresults:
                1. It should return the list of auth plugins
    """

    data = [('OP_TYPE', 'OP_SEARCH'),
            ('OP_SCOPE', 'instance')]

    response = requests.post(ca_url, params=data, headers=headers,
                             auth=('caadminn', 'SECRET123'))
    response.encoding = 'utf-8'
    assert response.status_code == 200
    assert 'Authentication failed' in response.content


def test_pki_ca_auth_plugins_read_auth_plugins():
    """
    :id: cc0776ea-5f3e-42d4-9d75-c843037eb7d7

    :Title: Test pki CA auth plugin, read the auth plugin.

    :Test: Test pki CA auth plugin, read the auth plugin.

    :Description: Read the CA auth plugin, using REST API.

    :Requirement: Certificate Authority Authentication Plugins

    :CaseComponent: \-

    :Setup: Use the subsystems setup in ansible to run subsystem commands

    :Steps:
            1. Request to URI http://pki1.example.com:<unsecure_port>/ca/auths
            2. Pass the data OP_TYPE=OP_SEARCH&OP_SCOPE=instance&RS_ID=AgentCertAuth&

    :Expectedresults:
                1. It should read the auth plugin
    """
    data = [('OP_TYPE', 'OP_READ'),
            ('OP_SCOPE', 'instance'),
            ('RS_ID', 'AgentCertAuth')]

    response = requests.post(ca_url, params=data, headers=headers,
                             auth=(constants.CA_ADMIN_USERNAME, constants.CA_PASSWORD))

    assert response.status_code == 200

    response.encoding = 'utf-8'
    assert 'implName=AgentCertAuth' in response.text


@pytest.mark.skip(reason="TODO need to fix")
def test_pki_ca_auth_plugins_add_agentCertAuth_plugin(ansible_module):
    """
    :id: 6e3c335e-6dac-44b3-8b69-f54e73bb4767

    :Title: Test pki CA auth plugin, add AgentCertAuth plugin through REST API

    :Test: Test pki CA auth plugin, add AgentCertAuth plugin through REST API.

    :Description: Add AgentCertPlugin through REST API

    :Requirement: Certificate Authority Authentication Plugins

    :CaseComponent: \-

    :Setup: Use the subsystems setup in ansible to run subsystem commands

    :Steps:
            1. Request to URI http://pki1.example.com:<unsecure_port>/ca/auths
            2. Pass the data OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=AgentCertAuth&

    :Expectedresults:
                1. Plugin should get added.
    """
    plugin_id = 'plug{}'.format(random.randint(111, 9999))
    data_add = [('OP_TYPE', 'OP_ADD'),
                ('OP_SCOPE', 'instance'),
                ('RS_ID', plugin_id),
                ('implName', 'AgentCertAuth')
                ]

    data_serach = [('OP_TYPE', 'OP_SEARCH'),
                   ('OP_SCOPE', 'instance'),
                   ('RS_ID', plugin_id)
                   ]

    add_response = requests.post(ca_url, params=data_add, headers=headers,
                                 auth=(constants.CA_ADMIN_USERNAME, constants.CA_PASSWORD))

    assert add_response.status_code == 200

    add_response.encoding = 'utf-8'

    search_response = requests.post(ca_url, params=data_serach, headers=headers,
                                    auth=(constants.CA_ADMIN_USERNAME, constants.CA_PASSWORD))

    assert search_response.status_code == 200

    search_response.encoding = 'utf-8'
    text = search_response.text.encode('utf-8').replace('%3Bvisible%3B', b'/')
    text = text.replace('%3Binvisible%3B', '/')
    if '\x00' in search_response.text:
        text = text.replace('\x00', '')
    text = text.split('&')
    all_plugs = [i.split("=")[0] for i in text]
    time.sleep(10)
    log = plugin_add_log.format(constants.CA_ADMIN_USERNAME, plugin_id, 'AgentCertAuth')
    signed_audit_logs = get_log(ansible_module)
    logs = re.findall('\[AuditEvent=CONFIG_AUTH.*', signed_audit_logs)
    assert log in logs[0]
    assert plugin_id in all_plugs
    newly_added_plugins.append(plugin_id)


def test_pki_ca_auth_plugins_add_CMCCertAuth_plugin(ansible_module):
    """
    :id: 67ee4c3f-8f62-4217-846b-c83bf2dc2b71

    :Title: Test pki CA auth plugin, Add new CMCAuth Plugin

    :Test: Test pki CA auth plugin, Add new CMCAuth plugin

    :Description: Add new CMCAuth plugin with REST API.

    :Requirement: Certificate Authority Authentication Plugins

    :CaseComponent: \-

    :Setup: Use the subsystems setup in ansible to run subsystem commands

    :Steps:
            1. Request to URI http://pki1.example.com:<unsecure_port>/ca/auths
            2. Pass the data OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=CMCAuth&implName=CMCAuth


    :Expectedresults:
                1. Plugin should get added.
    """
    plugin_id = 'plug{}'.format(random.randint(111, 9999))
    data_add = [('OP_TYPE', 'OP_ADD'),
                ('OP_SCOPE', 'instance'),
                ('RS_ID', plugin_id),
                ('implName', 'CMCAuth')
                ]

    data_serach = [('OP_TYPE', 'OP_SEARCH'),
                   ('OP_SCOPE', 'instance'),
                   ('RS_ID', plugin_id)
                   ]
    add_response = requests.post(ca_url, params=data_add, headers=headers,
                                 auth=(constants.CA_ADMIN_USERNAME, constants.CA_PASSWORD))

    assert add_response.status_code == 200

    add_response.encoding = 'utf-8'

    search_response = requests.post(ca_url, params=data_serach, headers=headers,
                                    auth=(constants.CA_ADMIN_USERNAME, constants.CA_PASSWORD))

    assert search_response.status_code == 200

    search_response.encoding = 'utf-8'
    text = search_response.text.encode('utf-8').replace('%3Bvisible%3B', b'/')
    text = text.replace('%3Binvisible%3B', '/')
    if '\x00' in search_response.text:
        text = text.replace('\x00', '')
    text = text.split('&')
    all_plugs = [i.split("=")[0] for i in text]

    log = plugin_add_log.format(constants.CA_ADMIN_USERNAME, plugin_id, 'CMCAuth')
    logs = get_log(ansible_module)
    assert log in logs
    assert plugin_id in all_plugs
    newly_added_plugins.append(plugin_id)


def test_pki_bug_1542210_ca_auth_plugins_add_uidPwdDirAuth_plugin(ansible_module):
    """
    :id: 741f8aca-0f81-4f80-a557-2c2f2fb4752b

    :Title: Test Bug: 1542210 pki ca auth plugin, add UidPwdDirAuth plugin using REST API.

    :Test: Test Bug: 1542210 pki ca auth plugin, add UidPwdDirAuth plugin using REST API.

    :Description: Add UidPwdDirAuth plugin using REST API.

    :Requirement: Certificate Authority Authentication Plugins

    :CaseComponent: \-

    :Setup: Use the subsystems setup in ansible to run subsystem commands

    :Steps:
        1. Request to URI http://pki1.example.com:<unsecure_port>/ca/auths
        2. Pass the data OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=UidPwdDirAuth&
        implName=UidPwdDirAuth&ldap.ldapconn.host=localhost&dnpattern=UID=test,OU=people,
        O=netscapecertificateserver&ldapStringAttributes=mail&ldap.ldapconn.version=3&
        ldap.ldapconn.port=3389&ldap.maxConn=10&ldap.basedn=dc=example,dc=org&ldap.password=
        SECret.123&ldap.ldapconn.secureConn=false&ldapByteAttributes=uid&
        3. Create post request through request module.
    :Expectedresults:
                1. Make sure that plugin should get added.
    """
    plugin_id = 'plug{}'.format(random.randint(111, 999))
    data = [('OP_TYPE', 'OP_ADD'),
            ('OP_SCOPE', 'instance'),
            ('RS_ID', plugin_id),
            ('implName', 'UidPwdDirAuth'),
            ('RULENAME', plugin_id),
            ('ldap.ldapconn.host', 'localhost'),
            ('dnpattern', 'UID=test,OU=people,O={}-CA'.format(constants.CA_INSTANCE_NAME)),
            ('ldapStringAttributes', 'mail'),
            ('ldap.ldapconn.version', '3'),
            ('ldap.ldapconn.port', constants.LDAP_PORT),
            ('ldap.maxConns', '10'),
            ('ldap.basedn', constants.LDAP_BASE_DN),
            ('ldap.password', constants.LDAP_PASSWD),
            ('ldap.minConns', '3'),
            ('ldap.ldapconn.secureConn', 'false'),
            ('ldapByteAttributes', 'uid'),
            ]

    search_response = requests.post(ca_url, params=data, headers=headers,
                                    auth=(constants.CA_ADMIN_USERNAME, constants.CA_PASSWORD))

    assert search_response.status_code == 200

    search_response.encoding = 'utf-8'
    text = search_response.text.encode('utf-8').replace('%3Bvisible%3B', b'/')
    text = text.replace('%3Binvisible%3B', '/')
    if '\x00' in search_response.text:
        text = text.replace('\x00', '')
    text = text.split('&')
    debug_logs = get_log(ansible_module, audit=False, debug=True)
    searchd_log = ",".join(re.findall('AdminServlet.*service\(\).*', debug_logs))
    logs = get_log(ansible_module)
    searched_audit_logs = ",".join(re.findall("AuditEvent=CONFIG_AUTH.*", logs))
    audit_logs = searched_audit_logs.replace(';', '')
    assert "param name='ldap.password' value='(sensitive)'" in searchd_log
    assert 'ldap.password;;(sensitive)' not in audit_logs
    assert 'implName=UidPwdDirAuth' in text[0]

    for k in data:
        i, j = k
        if i == 'OP_TYPE':
            assert 'Operation;;{}'.format(j) in logs
        elif i == 'OP_SCOPE':
            assert 'Scope;;{}'.format(j) in logs
        elif i == 'RS_ID':
            assert 'Resource;;{}'.format(j) in logs
        elif i == 'RULENAME':
            continue
        elif i == 'ldap.password':
            assert '{};;{}'.format(i, j) not in logs
        else:
            assert '{};;{}'.format(i, j) in logs

    newly_added_plugins.append(plugin_id)


def test_bug_1542210_pki_ca_auth_plugins_modify_uidPwdDirAuth_plugin(ansible_module):
    """
    :id: b74380bb-949e-4b05-b7f1-55cb915aa8c6

    :Title: Test Bug: 1542210 pki ca auth plugin, add UidPwdDirAuth plugin
            using REST API and modify it.

    :Test: Test Bug: 1542210 pki ca auth plugin, add UidPwdDirAuth plugin
            using REST API and modify it.

    :Description: Add UidPwdDirAuth plugin using REST API and modify it.

    :Requirement: Certificate Authority Authentication Plugins

    :CaseComponent: \-

    :Setup: Use the subsystems setup in ansible to run subsystem commands

    :Steps:
            1. Request to URI http://pki1.example.com:<unsecure_port>/ca/auths
            2. Pass the data OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=UidPwdDirAuth&
            implName=UidPwdDirAuth&ldap.ldapconn.host=localhost&dnpattern=UID=test,OU=people,
            O=netscapecertificateserver&ldapStringAttributes=mail&ldap.ldapconn.version=3&
            ldap.ldapconn.port=3389&ldap.maxConn=10&ldap.basedn=dc=example,dc=org&ldap.password=
            Secret123&ldap.ldapconn.secureConn=false&ldapByteAttributes=uid&
            3. Create post request through request module make sure that plugin get added.
            4. Modify the plugin using REST API.

    :Expectedresults:
                1. Make sure that plugin should get added.
                2. Make sure that plugin should get modified.
    """
    plugin_id = 'plug{}'.format(random.randint(111, 999))
    data = [('OP_TYPE', 'OP_ADD'),
            ('OP_SCOPE', 'instance'),
            ('RS_ID', plugin_id),
            ('implName', 'UidPwdDirAuth'),
            ('RULENAME', plugin_id),
            ('ldap.ldapconn.host', 'localhost'),
            ('dnpattern', 'UID=test,OU=people,O={}-CA'.format(constants.CA_INSTANCE_NAME)),
            ('ldapStringAttributes', 'mail'),
            ('ldap.ldapconn.version', '3'),
            ('ldap.ldapconn.port', constants.LDAP_PORT),
            ('ldap.maxConns', '10'),
            ('ldap.basedn', constants.LDAP_BASE_DN),
            ('ldap.password', constants.LDAP_PASSWD),
            ('ldap.minConns', '3'),
            ('ldap.ldapconn.secureConn', 'false'),
            ('ldapByteAttributes', 'uid'),
            ]

    data_mod = [('OP_TYPE', 'OP_MODIFY'),
                ('OP_SCOPE', 'instance'),
                ('RS_ID', plugin_id),
                ('implName', 'UidPwdDirAuth'),
                ('RULENAME', plugin_id),
                ('ldap.ldapconn.host', 'localhost'),
                ('dnpattern', 'UID=test,OU=people,O={}-CA'.format(constants.CA_INSTANCE_NAME)),
                ('ldapStringAttributes', 'mail'),
                ('ldap.ldapconn.version', '3'),
                ('ldap.ldapconn.port', constants.LDAP_PORT),
                ('ldap.maxConns', '10'),
                ('ldap.basedn', constants.LDAP_BASE_DN),
                ('ldap.password', constants.LDAP_PASSWD),
                ('ldap.minConns', '3'),
                ('ldap.ldapconn.secureConn', 'false'),
                ('ldapByteAttributes', 'uid'),
                ]

    add_response = requests.post(ca_url, params=data, headers=headers,
                                 auth=(constants.CA_ADMIN_USERNAME, constants.CA_PASSWORD))

    assert add_response.status_code == 200

    mod_response = requests.post(ca_url, params=data_mod, headers=headers,
                                 auth=(constants.CA_ADMIN_USERNAME, constants.CA_PASSWORD))

    assert mod_response.status_code == 200
    mod_response.encoding = 'utf-8'
    # text = mod_response.text.encode('utf-8').replace('%3Bvisible%3B', b'/')
    # text = text.replace('%3Binvisible%3B', '/')
    # if '\x00' in mod_response.text:
    #     text = text.replace('\x00', '')
    # text = text.split('&')

    debug_logs = get_log(ansible_module, audit=False, debug=True)
    searchd_log = ",".join(re.findall('AdminServlet.*service\(\).*', debug_logs))
    logs = get_log(ansible_module)
    searched_audit_logs = ",".join(re.findall("AuditEvent=CONFIG_AUTH.*", logs))
    audit_logs = searched_audit_logs.replace(';', '')
    assert "param name='ldap.password' value='(sensitive)'" in searchd_log
    assert constants.LDAP_PASSWD not in audit_logs

    for k in data_mod:
        i, j = k
        if i == 'OP_TYPE':
            assert 'Operation;;{}'.format(j) in logs
        elif i == 'OP_SCOPE':
            assert 'Scope;;{}'.format(j) in logs
        elif i == 'RS_ID':
            assert 'Resource;;{}'.format(j) in logs
        elif i == 'RULENAME':
            continue
        elif i == 'ldap.password':
            assert '{};;{}'.format(i, j) not in logs
        else:
            assert '{};;{}'.format(i, j) in logs

    newly_added_plugins.append(plugin_id)


def test_pki_bug_1542210_ca_auth_plugins_add_UidPwdPinDirAuth_plugin(ansible_module):
    """
    :id: 1ed3851f-4653-47ef-a411-b2b3decfd498

    :Title: Test Bug: 1542210 pki CA auth plugin, add UidPwdPinDirAuth plugin using REST API.

    :Test: Test Bug: 1542210 pki CA auth plugin, add UidPwdPinDirAuth plugin using REST API.

    :Description: Add UidPwdDirAuth plugin using REST API.

    :Requirement: Certificate Authority Authentication Plugins

    :CaseComponent: \-

    :Setup: Use the subsystems setup in ansible to run subsystem commands

    :Steps:
            1. Request to URI http://pki1.example.com:<unsecure_port>/ca/auths
            2. Pass the data OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=UidPwdPinDirAuth&
            implName=UidPwdPinDirAuth&ldap.ldapconn.host=localhost&dnpattern=UID=test,OU=people,
            O=netscapecertificateserver&ldapStringAttributes=mail&ldap.ldapconn.version=3&
            ldap.ldapconn.port=3389&ldap.maxConn=10&ldap.basedn=dc=example,dc=org&ldap.password=
            Secret123&ldap.ldapconn.secureConn=false&ldapByteAttributes=uid&
            3. Create post request through request module make sure that plugin get added.
            4. Modify the plugin using REST API.

    :Expectedresults:
                1. Make sure that plugin should get added.
    """
    plugin_id = 'plug{}'.format(random.randint(111, 999))

    data = [('OP_TYPE', 'OP_ADD'),
            ('OP_SCOPE', 'instance'),
            ('RS_ID', plugin_id),
            ('implName', 'UidPwdPinDirAuth'),
            ('RULENAME', plugin_id),
            ('ldap.ldapconn.host', 'localhost'),
            ('dnpattern', 'UID=test,OU=people,O={}-CA'.format(constants.CA_INSTANCE_NAME)),
            ('ldapStringAttributes', 'mail'),
            ('ldap.ldapconn.version', '3'),
            ('ldap.ldapconn.port', constants.LDAP_PORT),
            ('ldap.maxConns', '10'),
            ('ldap.basedn', constants.LDAP_BASE_DN),
            ('ldap.minConns', '3'),
            ('ldap.password', constants.CA_PASSWORD),
            ('ldap.ldapconn.secureConn', 'False'),
            ('ldapByteAttributes', 'mail'),
            ('pinAttr', 'pin'),
            ('ldap.ldapauth.clientCertNickname', ''),
            ('ldap.ldapauth.bindDN', constants.LDAP_BIND_DN),
            ('removePin', 'false'),
            ('ldap.ldapauth.authtype', 'BasicAuth'),
            ]

    add_response = requests.post(ca_url, params=data, headers=headers,
                                 auth=(constants.CA_ADMIN_USERNAME, constants.CA_PASSWORD))
    assert add_response.status_code == 200

    logs = get_log(ansible_module)
    debug_logs = get_log(ansible_module, audit=False, debug=True)

    for k in data:
        i, j = k
        if i == 'OP_TYPE':
            assert 'Operation;;{}'.format(j) in logs
        elif i == 'OP_SCOPE':
            assert 'Scope;;{}'.format(j) in logs
        elif i == 'RS_ID':
            assert 'Resource;;{}'.format(j) in logs
        elif i == 'RULENAME':
            continue
        elif i == 'ldap.password':
            assert '{};;{}'.format(i, j) not in logs
        else:
            assert '{};;{}'.format(i, j) in logs

    assert "param name='ldap.password' value='(sensitive)'" in debug_logs
    assert 'ldap.password;;{}'.format(constants.LDAP_PASSWD) not in logs
    newly_added_plugins.append(plugin_id)


def test_pki_bug_1542210_ca_auth_plugins_mod_UidPwdPinDirAuth_plugin(ansible_module):
    """
    :id: 54f0f6c4-5ce6-4bcb-8467-0da0843b9f70

    :Title: Test Bug: 1542210 pki ca auth plugin, add UidPwdPinDirAuth plugin using REST API and
    modify it.

    :Test: Test Bug: 1542210 pki ca auth plugin, add UidPwdPinDirAuth plugin using REST API and
    modify it.

    :Description: Add UidPwdPinDirAuth plugin using REST API and modify it.

    :Requirement: Certificate Authority Authentication Plugins

    :CaseComponent: \-

    :Setup: Use the subsystems setup in ansible to run subsystem commands

    :Steps:
            1. Request to URI http://pki1.example.com:<unsecure_port>/ca/auths
            2. Pass the data OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=UidPwdPinDirAuth&
            implName=UidPwdPinDirAuth&ldap.ldapconn.host=localhost&dnpattern=UID=test,OU=people,
            O=netscapecertificateserver&ldapStringAttributes=mail&ldap.ldapconn.version=3&
            ldap.ldapconn.port=3389&ldap.maxConn=10&ldap.basedn=dc=example,dc=org&ldap.password=
            Secret123&ldap.ldapconn.secureConn=false&ldapByteAttributes=uid&
            3. Create post request through request module make sure that plugin get added.
            4. Modify the plugin using REST API.

    :Expectedresults:
                1. Make sure that plugin should get added.
                2. Make sure that plugin should get modified.
    """
    plugin_id = 'plug{}'.format(random.randint(111, 999))

    data = [('OP_TYPE', 'OP_ADD'),
            ('OP_SCOPE', 'instance'),
            ('RS_ID', plugin_id),
            ('implName', 'UidPwdPinDirAuth'),
            ('RULENAME', plugin_id),
            ('ldap.ldapconn.host', 'localhost'),
            ('dnpattern', 'UID=test,OU=people,O={}-CA'.format(constants.CA_INSTANCE_NAME)),
            ('ldapStringAttributes', 'mail'),
            ('ldap.ldapconn.version', '3'),
            ('ldap.ldapconn.port', constants.LDAP_PORT),
            ('ldap.maxConns', '10'),
            ('ldap.basedn', constants.LDAP_BASE_DN),
            ('ldap.minConns', '3'),
            ('ldap.password', constants.CA_PASSWORD),
            ('ldap.ldapconn.secureConn', 'False'),
            ('ldapByteAttributes', 'mail'),
            ('pinAttr', 'pin'),
            ('ldap.ldapauth.clientCertNickname', ''),
            ('ldap.ldapauth.bindDN', constants.LDAP_BIND_DN),
            ('removePin', 'false'),
            ('ldap.ldapauth.authtype', 'BasicAuth'),
            ]

    mod_data = [('OP_TYPE', 'OP_MODIFY'),
                ('OP_SCOPE', 'instance'),
                ('RS_ID', plugin_id),
                ('implName', 'UidPwdPinDirAuth'),
                ('RULENAME', plugin_id),
                ('ldap.ldapconn.host', 'localhost'),
                ('dnpattern', 'UID=test,OU=people,O={}-CA'.format(constants.CA_INSTANCE_NAME)),
                ('ldapStringAttributes', 'mail'),
                ('ldap.ldapconn.version', '3'),
                ('ldap.ldapconn.port', constants.LDAP_PORT),
                ('ldap.maxConns', '10'),
                ('ldap.basedn', constants.LDAP_BASE_DN),
                ('ldap.minConns', '3'),
                ('ldap.password', constants.LDAP_PASSWD),
                ('ldap.ldapconn.secureConn', 'False'),
                ('ldapByteAttributes', 'mail'),
                ('pinAttr', 'pin'),
                ('ldap.ldapauth.clientCertNickname', ''),
                ('ldap.ldapauth.bindDN', constants.LDAP_BIND_DN),
                ('removePin', 'false'),
                ('ldap.ldapauth.authtype', 'BasicAuth'),
                ]

    add_response = requests.post(ca_url, params=data, headers=headers,
                                 auth=(constants.CA_ADMIN_USERNAME, constants.CA_PASSWORD))

    assert add_response.status_code == 200

    add_response.encoding = 'utf-8'

    mod_response = requests.post(ca_url, params=mod_data, headers=headers,
                                 auth=(constants.CA_ADMIN_USERNAME, constants.CA_PASSWORD))

    assert mod_response.status_code == 200

    logs = get_log(ansible_module)
    debug_logs = get_log(ansible_module, audit=False, debug=True)

    for k in mod_data:
        i, j = k
        if i == 'OP_TYPE':
            assert 'Operation;;{}'.format(j) in logs
        elif i == 'OP_SCOPE':
            assert 'Scope;;{}'.format(j) in logs
        elif i == 'RS_ID':
            assert 'Resource;;{}'.format(j) in logs
        elif i == 'RULENAME':
            continue
        elif i == 'ldap.password':
            assert '{};;{}'.format(i, j) not in logs
        else:
            assert '{};;{}'.format(i, j) in logs

    assert "param name='ldap.password' value='(sensitive)'" in debug_logs
    assert 'ldap.password;;{}'.format(constants.LDAP_PASSWD) not in logs
    newly_added_plugins.append(plugin_id)


def remove_added_plugins():
    """
    This method will remove the added plugins.
    :return:
    """
    for plug in newly_added_plugins:
        data_del = [('OP_TYPE', 'OP_DELETE'),
                    ('OP_SCOPE', 'instance'),
                    ('RS_ID', plug)]

        search_response = requests.post(ca_url, params=data_del, headers=headers,
                                        auth=(constants.CA_ADMIN_USERNAME, constants.CA_PASSWORD))
        search_response.encoding = 'utf-8'
        text = search_response.text.encode('utf-8').replace('%3Bvisible%3B', b'/')
        text = text.replace('%3Binvisible%3B', '/')
        if '\x00' in search_response.text:
            text = text.replace('\x00', '')
        text = text.split('&')
        all_plugs = [i.split("=")[0] for i in text]

        assert plug not in all_plugs


def test_pki_bug_1542210_ca_auth_plugins_add_SharedToken_plugin(ansible_module):
    """
    :id: 086a1e17-3da5-47ac-ad21-90d06f1ec4a1

    :Title: Test Bug: 1542210 pki ca auth plugin, add SharedToken plugin using REST API.

    :Test: Test Bug: 1542210 pki ca auth plugin, add SharedToken plugin using REST API.

    :Description: Add SharedToken plugin using REST API.

    :Requirement: Certificate Authority Authentication Plugins

    :CaseComponent: \-

    :Setup: Use the subsystems setup in ansible to run subsystem commands

    :Steps:
            1. Request to URI http://pki1.example.com:<unsecure_port>/ca/auths
            2. Pass the data OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=SharedToken&
            implName=SharedToken&ldap.ldapconn.host=localhost&dnpattern=UID=test,OU=people,
            O=netscapecertificateserver&ldapStringAttributes=mail&ldap.ldapconn.version=3&
            ldap.ldapconn.port=3389&ldap.maxConn=10&ldap.basedn=dc=example,dc=org&ldap.password=
            Secret123&ldap.ldapconn.secureConn=false&ldapByteAttributes=uid&
            3. Create post request through request module.

    :Expectedresults:
                1. Make sure that plugin should get added.
    """
    plugin_id = 'plug{}'.format(random.randint(111, 999))
    data = [('OP_TYPE', 'OP_ADD'),
            ('OP_SCOPE', 'instance'),
            ('RS_ID', plugin_id),
            ('implName', 'SharedToken'),
            ('RULENAME', plugin_id),
            ('ldap.ldapconn.host', 'localhost'),
            ('dnpattern', 'UID=test,OU=people,O={}-CA'.format(constants.CA_INSTANCE_NAME)),
            ('ldapStringAttributes', 'mail'),
            ('ldap.ldapconn.version', '3'),
            ('ldap.ldapconn.port', constants.LDAP_PORT),
            ('ldap.maxConns', '10'),
            ('ldap.basedn', constants.LDAP_BASE_DN),
            ('ldap.password', constants.LDAP_PASSWD),
            ('ldap.minConns', '3'),
            ('ldap.ldapconn.secureConn', 'false'),
            ('ldapByteAttributes', 'uid'),
            ('ldap.ldapauth.authtype', 'BasicAuth'),
            ('ldap.ldapauth.bindDN', constants.LDAP_BIND_DN)
            ]

    search_response = requests.post(ca_url, params=data, headers=headers,
                                    auth=(constants.CA_ADMIN_USERNAME, constants.CA_PASSWORD))

    assert search_response.status_code == 200

    search_response.encoding = 'utf-8'
    text = search_response.text.encode('utf-8').replace('%3Bvisible%3B', b'/')
    text = text.replace('%3Binvisible%3B', '/')
    if '\x00' in search_response.text:
        text = text.replace('\x00', '')
    text = text.split('&')

    logs = get_log(ansible_module)
    debug_logs = get_log(ansible_module, audit=False, debug=True)
    assert "param name='ldap.password' value='(sensitive)'" in debug_logs
    assert 'ldap.password;;{}'.format(constants.LDAP_PASSWD) not in logs
    assert 'implName=SharedToken' in text[0]

    for k in data:
        i, j = k
        if i == 'OP_TYPE':
            assert 'Operation;;{}'.format(j) in logs
        elif i == 'OP_SCOPE':
            assert 'Scope;;{}'.format(j) in logs
        elif i == 'RS_ID':
            assert 'Resource;;{}'.format(j) in logs
        elif i == 'RULENAME':
            continue
        elif i == 'ldap.password':
            assert '{};;{}'.format(i, j) not in logs
        else:
            assert '{};;{}'.format(i, j) in logs

    newly_added_plugins.append(plugin_id)


def test_bug_1542210_pki_ca_auth_plugins_modify_SharedToken_plugin(ansible_module):
    """
    :id: b3108fd1-8ea7-4bb6-ae0a-e57cab4a203

    :Title: Test Bug: 1542210 pki ca auth plugin, add SharedToken plugin
            using REST API and modify it.

    :Test: Test Bug: 1542210 pki ca auth plugin, add SharedToken plugin
            using REST API and modify it.

    :Description: Add SharedToken plugin using REST API and modify it.

    :Requirement: Certificate Authority Authentication Plugins

    :CaseComponent: \-

    :Setup: Use the subsystems setup in ansible to run subsystem commands

    :Steps:
            1. Request to URI http://pki1.example.com:<unsecure_port>/ca/auths
            2. Pass the data OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=SharedToken&
            implName=SharedToken&ldap.ldapconn.host=localhost&dnpattern=UID=test,OU=people,
            O=netscapecertificateserver&ldapStringAttributes=mail&ldap.ldapconn.version=3&
            ldap.ldapconn.port=3389&ldap.maxConn=10&ldap.basedn=dc=example,dc=org&ldap.password=
            Secret123&ldap.ldapconn.secureConn=false&ldapByteAttributes=uid&
            3. Create post request through request module make sure that plugin get added.
            4. Modify the plugin using REST API.

    :Expectedresults:
                1. Make sure that plugin should get added.
                2. Make sure that plugin should get modified.
    """
    plugin_id = 'plug{}'.format(random.randint(111, 999))
    data = [('OP_TYPE', 'OP_ADD'),
            ('OP_SCOPE', 'instance'),
            ('RS_ID', plugin_id),
            ('implName', 'SharedToken'),
            ('RULENAME', plugin_id),
            ('ldap.ldapconn.host', 'localhost'),
            ('dnpattern', 'UID=test,OU=people,O={}-CA'.format(constants.CA_INSTANCE_NAME)),
            ('ldapStringAttributes', 'mail'),
            ('ldap.ldapconn.version', '3'),
            ('ldap.ldapconn.port', constants.LDAP_PORT),
            ('ldap.maxConns', '10'),
            ('ldap.basedn', constants.LDAP_BASE_DN),
            ('ldap.password', constants.LDAP_PASSWD),
            ('ldap.minConns', '3'),
            ('ldap.ldapconn.secureConn', 'false'),
            ('ldapByteAttributes', 'uid'),
            ('ldap.ldapauth.authtype', 'BasicAuth'),
            ('ldap.ldapauth.bindDN', constants.LDAP_BIND_DN)
            ]

    data_mod = [('OP_TYPE', 'OP_MODIFY'),
                ('OP_SCOPE', 'instance'),
                ('RS_ID', plugin_id),
                ('implName', 'SharedToken'),
                ('RULENAME', plugin_id),
                ('ldap.ldapconn.host', 'localhost'),
                ('dnpattern', 'UID=test,OU=people,O={}-CA'.format(constants.CA_INSTANCE_NAME)),
                ('ldapStringAttributes', 'mail'),
                ('ldap.ldapconn.version', '3'),
                ('ldap.ldapconn.port', constants.LDAP_PORT),
                ('ldap.maxConns', '10'),
                ('ldap.basedn', constants.LDAP_BASE_DN),
                ('ldap.password', constants.LDAP_PASSWD),
                ('ldap.minConns', '3'),
                ('ldap.ldapconn.secureConn', 'false'),
                ('ldapByteAttributes', 'uid'),
                ('ldap.ldapauth.authtype', 'BasicAuth'),
                ('ldap.ldapauth.bindDN', constants.LDAP_BIND_DN)
                ]

    add_response = requests.post(ca_url, params=data, headers=headers,
                                 auth=(constants.CA_ADMIN_USERNAME, constants.CA_PASSWORD))

    assert add_response.status_code == 200

    mod_response = requests.post(ca_url, params=data_mod, headers=headers,
                                 auth=(constants.CA_ADMIN_USERNAME, constants.CA_PASSWORD))

    assert mod_response.status_code == 200
    mod_response.encoding = 'utf-8'
    text = mod_response.text.encode('utf-8').replace('%3Bvisible%3B', b'/')
    text = text.replace('%3Binvisible%3B', '/')
    if '\x00' in mod_response.text:
        text = text.replace('\x00', '')
    text = text.split('&')

    logs = get_log(ansible_module)
    debug_logs = get_log(ansible_module, audit=False, debug=True)

    assert "param name='ldap.password' value='(sensitive)'" in debug_logs
    assert 'ldap.password;;{}'.format(constants.LDAP_PASSWD) not in logs

    for k in data_mod:
        i, j = k
        if i == 'OP_TYPE':
            assert 'Operation;;{}'.format(j) in logs
        elif i == 'OP_SCOPE':
            assert 'Scope;;{}'.format(j) in logs
        elif i == 'RS_ID':
            assert 'Resource;;{}'.format(j) in logs
        elif i == 'RULENAME':
            continue
        elif i == 'ldap.password':
            assert '{};;{}'.format(i, j) not in logs
        else:
            assert '{};;{}'.format(i, j) in logs

    newly_added_plugins.append(plugin_id)


def revert_setup(ansible_module):
    ansible_module.lineinfile(path=ca_cfg_path, regexp="debug.level=5", line="debug.level=10")
    restart_instance(ansible_module)
    time.sleep(15)    
