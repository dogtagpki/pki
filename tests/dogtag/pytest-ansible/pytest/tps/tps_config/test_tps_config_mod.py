#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI TPS CONFIG CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki tps cli commands needs to be tested:
#   pki tps-config-mod
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Sumedh Sidhaye <ssidhaye@redhat.com>
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
import os
import sys
from xml.etree import ElementTree

import pytest
from pki.testlib.common.certlib import *

try:
    from pki.testlib.common import constants
except Exception:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

REVOKED_CERT_MESSAGE = ["FATAL: SSL alert received: CERTIFICATE_REVOKED"]
EXPIRED_CERT_MESSAGE = ["FATAL: SSL alert received: CERTIFICATE_EXPIRED"]
HOST = 'pki1.example.com'

@pytest.mark.setup
def test_setup(ansible_module):
    global HOST
    cert_setup = CertSetup(nssdb=constants.NSSDB,
                           db_pass=constants.CLIENT_DATABASE_PASSWORD,
                           host=HOST,
                           port=constants.CA_HTTP_PORT,
                           nick="'{}'".format(constants.CA_ADMIN_NICK))
    cert_setup.create_certdb(ansible_module)
    cert_setup.import_ca_cert(ansible_module)
    cert_setup.import_admin_p12(ansible_module, 'ca')
    cert_setup.setup_role_users(ansible_module, 'ca', constants.CA_ADMIN_NICK, duration='minute')
    tps_cert_setup = CertSetup(nssdb=constants.NSSDB,
                               db_pass=constants.CLIENT_DATABASE_PASSWORD,
                               host=HOST,
                               port=constants.TPS_HTTP_PORT,
                               nick="'{}'".format(constants.TPS_ADMIN_NICK))
    tps_cert_setup.import_admin_p12(ansible_module, 'tps')
    tps_cert_setup.setup_role_users(ansible_module, 'tps', constants.TPS_ADMIN_NICK,
                                    duration='minute')
    tpsconfig_show_output = ansible_module.pki(
        cli='tps-config-show',
        nssdb=constants.NSSDB,
        port=constants.TPS_HTTPS_PORT,
        protocol='https',
        certnick='TPS_AdminV',
        extra_args='--output /tmp/tps_config.xml'
    )
    ansible_module.fetch(src='/tmp/tps_config.xml', dest='/tmp/tps_config.xml', flat=True)
    xml_file = ElementTree.parse('/tmp/tps_config.xml')
    for element in xml_file.find("Properties"):
        if element.attrib['name'] == "general.search.sizelimit.default":
            element.text = "1"
        if element.attrib['name'] == "general.search.sizelimit.max":
            element.text = "1"
    xml_file.write('/tmp/tps_config_edited.xml')
    ansible_module.copy(src='/tmp/tps_config_edited.xml', dest='/tmp/tps_config.xml')

def test_tpsconfigmod_validnicks(ansible_module):
    """
    :Title: Test tps-config-mod with valid Admin, Agent and Operator Certificates

    :Description: Test tps-config-mod with valid Admin, Agent and Operator Certificates

    :Requirement:

    :Setup: Use pki setup via ansible playbooks

    :Steps: 1. Run tps-config-mod with valid Admin certificate

    :Expectedresults: 1. The command should be able to modify the config using valid Admin certificate

    :Automated: Yes
    """
    tpsconfigmod_output = ansible_module.pki(
        cli='tps-config-mod',
        extra_args='--input /tmp/tps_config.xml',
        nssdb=constants.NSSDB,
        port=constants.TPS_HTTPS_PORT,
        protocol='https',
        certnick='TPS_AdminV',
    )
    for result in tpsconfigmod_output.values():
        assert "Updated configuration" in result['stdout']
        assert 'general.search.sizelimit.default: 1' in result['stdout']
        assert 'general.search.sizelimit.max: 1' in result['stdout']

    CS_cfg_content = ansible_module.command("cat %s" %
                                            "/var/lib/pki/{}/tps/conf/CS.cfg".format(constants.TPS_INSTANCE_NAME))
    for result in CS_cfg_content.values():
        assert "general.search.sizelimit.default=1" in result['stdout']
        assert "general.search.sizelimit.max=1" in result['stdout']


@pytest.mark.parametrize("certnick,expected", [
    ("TPS_AdminR", REVOKED_CERT_MESSAGE),
    ("TPS_AdminE", EXPIRED_CERT_MESSAGE),
    ("TPS_AgentR", REVOKED_CERT_MESSAGE),
    ("TPS_AgentE", EXPIRED_CERT_MESSAGE),
    ("TPS_OperatorR", REVOKED_CERT_MESSAGE),
    ("TPS_OperatorE", EXPIRED_CERT_MESSAGE),
])
def test_tpsconfigmod_othernicks(ansible_module, certnick, expected):
    """
    :Title: Test tps-config-mod revoked and expired Admin, Agent and Operator Certificates

    :Description: Test tps-config-mod revoked and expired Admin, Agent and Operator Certificates

    :Requirement:

    :Setup: Use pki setup via ansible playbooks

    :Steps: 1. Run tps-config-mod using revoked and expired Admin, Agent and Operator Certificates

    :Expectedresults: 1. The command should not be able to modify configuration with revoked and expired certificates

    :Automated: Yes
    """
    tpsconfig_mod_output = ansible_module.pki(
        cli='tps-config-mod',
        extra_args='--input /tmp/tps_config.xml',
        nssdb=constants.NSSDB,
        port=constants.TPS_HTTPS_PORT,
        protocol='https',
        certnick=certnick,
    )
    for result in tpsconfig_mod_output.values():
        for iter in expected:
            assert iter in result['stderr_lines']

