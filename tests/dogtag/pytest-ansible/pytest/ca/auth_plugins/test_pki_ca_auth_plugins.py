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

import os
import random
import sys

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

newly_added_plugins = []

plugin_add_log = "[AuditEvent=CONFIG_AUTH][SubjectID={}][Outcome=Success][ParamNameValPairs=" \
                 "Scope;;instance+Operation;;OP_ADD+Resource;;{}+implName;;{}] " \
                 "authentication configuration parameter(s) change"

plugin_del_log = "[AuditEvent=CONFIG_AUTH][SubjectID={}][Outcome=Success][ParamNameValPairs=" \
                 "Scope;;instance+Operation;;OP_DELETE+Resource;;{}] authentication " \
                 "configuration parameter(s) change"

ca_url = 'http://pki1.example.com:{}/ca/auths'.format(constants.CA_HTTP_PORT)


@pytest.fixture(scope='module', autouse=True)
def plugin_conf(request):
    request.addfinalizer(remove_added_plugins)


def get_log(ansible_module, subsystem='ca', audit=True, debug=False):
    logs = None
    s = subsystem.upper()
    if s in ['CA', 'KRA', 'OCSP', 'TKS', 'TPS']:
        s = eval("constants.{}_INSTANCE_NAME".format(s))
        if audit:
            logs = ansible_module.command('tail -n10 /var/log/pki/{}/ca/signedAudit/'
                                          'ca_audit'.format(s))
        elif debug:
            logs = ansible_module.command('tail -n100 /var/log/pki/{}/ca/'
                                          'debug'.format(s))
        for _, res in logs.items():
            if res['rc'] == 0:
                return res['stdout']


def test_pki_ca_auth_plugins_list():
    """
    :Title: Test pki ca auth plugins list using REST API.
    :Description: List the CA subsystem auth plugins using REST API
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
    :Title: Test pki ca auth plugins list using REST API with invalid credential.
    :Description: List the CA subsystem auth plugins using REST API with invalid credential
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
    :Title: Test pki CA auth plugin, read the auth plugin.
    :Description: Read the CA auth plugin, using REST API.
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


def test_pki_ca_auth_plugins_add_agentCertAuth_plugin(ansible_module):
    """
    :Title: Test pki CA auth plugin, add AgentCertAuth plugin through REST API
    :Description: Add AgentCertPlugin through REST API
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

    log = plugin_add_log.format(constants.CA_ADMIN_USERNAME, plugin_id, 'AgentCertAuth')
    signed_audit_logs = get_log(ansible_module)
    assert log in signed_audit_logs
    assert plugin_id in all_plugs
    newly_added_plugins.append(plugin_id)


def test_pki_ca_auth_plugins_add_CMCCertAuth_plugin(ansible_module):
    """
    :Title: Test pki CA auth plugin, Add new CMCAuth Plugin
    :Description: Add new CMCAuth plugin with REST API.
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


@pytest.mark.xfail(reason="BZ: 1548203")
def test_pki_bug_1542210_ca_auth_plugins_add_uidPwdDirAuth_plugin(ansible_module):
    """
    :Title: Test Bug: 1542210 pki ca auth plugin, add UidPwdDirAuth plugin using REST API.
    :Description: Add UidPwdDirAuth plugin using REST API.
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

    logs = get_log(ansible_module)
    debug_logs = get_log(ansible_module, audit=False, debug=True)

    assert "param name='ldap.password' value='(sensitive)'" in debug_logs
    assert 'ldap.password;;{}'.format(constants.LDAP_PASSWD) not in logs
    assert plugin_id in text

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
        else:
            assert '{};;{}'.format(i, j) in logs

    newly_added_plugins.append(plugin_id)


@pytest.mark.xfail(reason="BZ: 1548203")
def test_bug_1542210_pki_ca_auth_plugins_modify_uidPwdDirAuth_plugin(ansible_module):
    """
    :Title: Test Bug: 1542210 pki ca auth plugin, add UidPwdDirAuth plugin
            using REST API and modify it.
    :Description: Add UidPwdDirAuth plugin using REST API and modify it.
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Request to URI http://pki1.example.com:<unsecure_port>/ca/auths
        2. Pass the data OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=UidPwdDirAuth&
        implName=UidPwdDirAuth&ldap.ldapconn.host=localhost&dnpattern=UID=test,OU=people,
        O=netscapecertificateserver&ldapStringAttributes=mail&ldap.ldapconn.version=3&
        ldap.ldapconn.port=3389&ldap.maxConn=10&ldap.basedn=dc=example,dc=org&ldap.password=
        SECret.123&ldap.ldapconn.secureConn=false&ldapByteAttributes=uid&
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
    text = mod_response.text.encode('utf-8').replace('%3Bvisible%3B', b'/')
    text = text.replace('%3Binvisible%3B', '/')
    if '\x00' in mod_response.text:
        text = text.replace('\x00', '')
    text = text.split('&')

    logs = get_log(ansible_module)
    debug_logs = get_log(ansible_module, audit=False, debug=True)

    assert "param name='ldap.password' value='(sensitive)'" in debug_logs
    assert 'ldap.password;;{}'.format(constants.LDAP_PASSWD) not in logs
    assert plugin_id in text

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
        else:
            assert '{};;{}'.format(i, j) in logs

    newly_added_plugins.append(plugin_id)


@pytest.mark.xfail(reason="BZ: 1548203")
def test_pki_bug_1542210_ca_auth_plugins_add_UidPwdPinDirAuth_plugin(ansible_module):
    """
    :Title: Test Bug: 1542210 pki CA auth plugin, add UidPwdPinDirAuth plugin using REST API.
    :Description: Add UidPwdDirAuth plugin using REST API.
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Request to URI http://pki1.example.com:<unsecure_port>/ca/auths
        2. Pass the data OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=UidPwdPinDirAuth&
        implName=UidPwdPinDirAuth&ldap.ldapconn.host=localhost&dnpattern=UID=test,OU=people,
        O=netscapecertificateserver&ldapStringAttributes=mail&ldap.ldapconn.version=3&
        ldap.ldapconn.port=3389&ldap.maxConn=10&ldap.basedn=dc=example,dc=org&ldap.password=
        SECret.123&ldap.ldapconn.secureConn=false&ldapByteAttributes=uid&
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
        else:
            assert '{};;{}'.format(i, j) in logs

    assert "param name='ldap.password' value='(sensitive)'" in debug_logs
    assert 'ldap.password;;{}'.format(constants.LDAP_PASSWD) not in logs
    newly_added_plugins.append(plugin_id)


@pytest.mark.xfail(reason="BZ: 1548203")
def test_pki_bug_1542210_ca_auth_plugins_mod_UidPwdPinDirAuth_plugin(ansible_module):
    """
    :Title: Test Bug: 1542210 pki ca auth plugin, add UidPwdPinDirAuth plugin using REST API and
    modify it.
    :Description: Add UidPwdPinDirAuth plugin using REST API and modify it.
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Request to URI http://pki1.example.com:<unsecure_port>/ca/auths
        2. Pass the data OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=UidPwdPinDirAuth&
        implName=UidPwdPinDirAuth&ldap.ldapconn.host=localhost&dnpattern=UID=test,OU=people,
        O=netscapecertificateserver&ldapStringAttributes=mail&ldap.ldapconn.version=3&
        ldap.ldapconn.port=3389&ldap.maxConn=10&ldap.basedn=dc=example,dc=org&ldap.password=
        SECret.123&ldap.ldapconn.secureConn=false&ldapByteAttributes=uid&
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

    mod_data = [('OP_TYPE', 'OP_ADD'),
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


@pytest.mark.xfail(reason="BZ: 1548203")
def test_pki_bug_1542210_ca_auth_plugins_add_SharedToken_plugin(ansible_module):
    """
    :Title: Test Bug: 1542210 pki ca auth plugin, add SharedToken plugin using REST API.
    :Description: Add SharedToken plugin using REST API.
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Request to URI http://pki1.example.com:<unsecure_port>/ca/auths
        2. Pass the data OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=SharedToken&
        implName=SharedToken&ldap.ldapconn.host=localhost&dnpattern=UID=test,OU=people,
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
    assert plugin_id in text

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
        else:
            assert '{};;{}'.format(i, j) in logs

    newly_added_plugins.append(plugin_id)


@pytest.mark.xfail(reason="BZ: 1548203")
def test_bug_1542210_pki_ca_auth_plugins_modify_SharedToken_plugin(ansible_module):
    """
    :Title: Test Bug: 1542210 pki ca auth plugin, add SharedToken plugin
            using REST API and modify it.
    :Description: Add SharedToken plugin using REST API and modify it.
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Request to URI http://pki1.example.com:<unsecure_port>/ca/auths
        2. Pass the data OP_TYPE=OP_ADD&OP_SCOPE=instance&RS_ID=SharedToken&
        implName=SharedToken&ldap.ldapconn.host=localhost&dnpattern=UID=test,OU=people,
        O=netscapecertificateserver&ldapStringAttributes=mail&ldap.ldapconn.version=3&
        ldap.ldapconn.port=3389&ldap.maxConn=10&ldap.basedn=dc=example,dc=org&ldap.password=
        SECret.123&ldap.ldapconn.secureConn=false&ldapByteAttributes=uid&
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
    assert plugin_id in text

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
        else:
            assert '{};;{}'.format(i, j) in logs

    newly_added_plugins.append(plugin_id)

