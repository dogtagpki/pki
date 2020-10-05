#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Automation of bz_1789907: CVE-2019-10221 Reflected
#                cross site scripting in getcookies?url= endpoint in CA
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Pritam Singh <prisingh@redhat.com>
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
import os
import pytest
import requests
import time
import sys

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)

ca_cfg_path = '/var/lib/pki' + '/' + constants.CA_INSTANCE_NAME + '/' + 'ca/conf/CS.cfg'
payload = '"><img src=x onerror=alert(document.domain)>'
xss_url = 'https://{}:{}/ca/admin/ca/getCookie?url={}'.format(constants.MASTER_HOSTNAME,
                                                              constants.CA_HTTPS_PORT, payload)


@pytest.fixture(autouse=True)
def topo00_setup_for_ldap_and_ca(ansible_module):
    """
    :Title: Topology-00 setup for ldap, ca
    :Description: setup ldap, ca
    :Requirement:
    :CaseComponent:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Install Ldap server
        2. Install CA
        3. Remove CA
        4. Remove LDAP
    :Expected Results:
        1. It should install ldap, ca
    """
    # Setup DS instance
    ansible_module.command('cp -R /tmp/test_dir/ /tmp/test_conf')
    log.info('Installing DS')
    out = ansible_module.shell('dscreate from-file /tmp/test_conf/ldap.cfg')
    for result in out.values():
        assert result['rc'] == 0
        log.info("Setup DS instance.")

    # Setup CA instance
    log.info('Installing CA')
    install_ca = ansible_module.shell('pkispawn -s CA -f /tmp/test_conf/ca.cfg')
    for result in install_ca.values():
        assert result['rc'] == 0
        log.info("CA Installed successfully")

    yield

    # Remove CA instance
    log.info('Removing CA')
    remove_ca = ansible_module.shell('pkidestroy -s CA -i {}'.format(constants.CA_INSTANCE_NAME))
    for result in remove_ca.values():
        assert result['rc'] == 0
        log.info("CA removed successfully.")
        time.sleep(5)

    # Remove Ldap server
    log.info('Removing DS')
    remove_ldap = ansible_module.shell('dsctl topology-00-testingmaster remove --do-it')
    for result in remove_ldap.values():
        assert result['rc'] == 0
        log.info("LDAP removed successfully.")


def test_pki_ca_reflected_xss_in_getcookies_url_endpoint_in_ca(ansible_module):
    """
    :Title: Test pki ca reflected xss in getcookies?url= endpoint in ca
    :Description: Test pki ca reflected xss in getcookies?url= endpoint in ca
    :Requirement:
    :CaseComponent:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Install CA
        2. Import ca_admin_cert.p12 in browser
        3. Visit: https://<hostname_or_ip>:<secure_port>/ca/admin/ca/getCookie?url=
           "><img src=x onerror=alert(document.domain)>
    :ExpectedResults:
        1. It should not trigger XSS.
    :Automated: Yes
    """
    # Get certificates
    ansible_module.lineinfile(path=ca_cfg_path, regexp="ca.enableNonces=true", line="ca.enableNonces=false")
    ansible_module.command('pki-server restart {}'.format(constants.CA_INSTANCE_NAME))
    time.sleep(5)

    ansible_module.shell("openssl pkcs12 -in /opt/{}/ca_admin_cert.p12 "
                         "-out /tmp/auth_cert.pem -nodes -passin pass:{}".format(constants.CA_INSTANCE_NAME,
                                                                                 constants.CLIENT_DATABASE_PASSWORD))
    ansible_module.fetch(src="/tmp/auth_cert.pem", dest="/tmp/auth_cert.pem", flat="yes")
    ansible_module.fetch(src='/var/lib/pki/{}/alias/ca.crt'.format(constants.CA_INSTANCE_NAME),
                         dest='/tmp/ca.crt', flat="yes")

    # Detect RXSS with requests
    response = requests.get(xss_url, verify='/tmp/ca.crt', cert='/tmp/auth_cert.pem')
    if response.status_code == 200:
        if payload.lower() in response.text.lower():
            assert payload.lower() in response.text.lower()
            log.info('Vulnerable: Payload is not getting sanitized')
            pytest.fail('Seems vulnerable with Reflected XSS')
        else:
            assert payload.lower() not in response.text.lower()
            log.info('Successfully sanitized the XSS payload')
    else:
        log.error('Failed to run the request')
        pytest.fail('Failed to execute the request command')

    # Fix nonce
    ansible_module.lineinfile(path=ca_cfg_path, regexp="ca.enableNonces=false", line="ca.enableNonces=true")
    ansible_module.command('pki-server restart {}'.format(constants.CA_INSTANCE_NAME))

    # Delete certificate
    ansible_module.command('rm -rf /tmp/ca.crt /tmp/auth_cert.pem /tmp/test_conf/')
    for i in ['/tmp/ca.crt', '/tmp/auth_cert.pem']:
        os.remove(i)
