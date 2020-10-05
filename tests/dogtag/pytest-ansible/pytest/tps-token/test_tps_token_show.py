"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI TPS-TOKEN-SHOW tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki tps commands needs to be tested:
#   pki tps-token-show
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Geetika Kapoor <gkapoor@redhat.com>
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
"""

import pytest
import ansible
import logging
from ansible.inventory import Inventory
from pytest_ansible import plugin
import ansible.constants
import os
import sys
import time

from pki.testlib.common.certlib import *
import random

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
TOPOLOGY = constants.CA_INSTANCE_NAME.split("-")[-2]

if TOPOLOGY == '01':
    ca_instance_name = 'pki-tomcat'
    topology_name = 'topology-01-CA'
else:
    ca_instance_name = constants.CA_INSTANCE_NAME
    topology_name = constants.CA_INSTANCE_NAME

ldap_path = "/tmp/test_dir/ldap_user_add.cfg"
enroll_path = '/tmp/test_dir/token_enroll.txt'
HOST = constants.MASTER_HOSTNAME


@pytest.mark.setup
def test_setup(ansible_module):
    """
             :Title: Test for running tps-token-show command.
             :Description: This is test for tps-token-show command.


             :Type: Functional
             :steps:

             1. Create custom nssdb and import Admin certificates.
             2. Import CA, TPS certificates in custom database.
             3. Add LDAP user.
             4. Enroll a token.
             5. Display the tokens.

             :setup:
             1. Install CA, KRA, OCSP, TKS and TPS


             :Expected Results:
             1. Installation is successful.
             2. tps-token-show command should succeed for valid tokens.
             3. tps-token-show command should fail for invalid tokens.

       """
    cert_setup = CertSetup(nssdb=constants.NSSDB,
                           db_pass=constants.CLIENT_DATABASE_PASSWORD,
                           host=HOST,
                           port=constants.CA_HTTP_PORT,
                           nick="'{}'".format(constants.CA_ADMIN_NICK))
    cert_setup.create_certdb(ansible_module)
    cert_setup.import_ca_cert(ansible_module)
    cert_setup.import_admin_p12(ansible_module, 'ca')
    tps_cert_setup = CertSetup(nssdb=constants.NSSDB,
                               db_pass=constants.CLIENT_DATABASE_PASSWORD,
                               host=HOST,
                               port=constants.TPS_HTTP_PORT,
                               nick="'{}'".format(constants.TPS_ADMIN_NICK))
    tps_cert_setup.import_admin_p12(ansible_module, 'tps')
    # Creating ldap user
    ldap_user_out = ansible_module.shell('ldapadd -h {} -p {} -D "cn=Directory Manager" -w {} -f {}'
                                         ''.format(constants.MASTER_HOSTNAME, constants.LDAP_PORT,
                                                   constants.LDAP_PASSWD,
                                                   ldap_path))
    for result in ldap_user_out.values():
        if result['rc'] == 0:
            assert "adding new entry" in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            log.info("Failed to run : '{}'".format(result['cmd']))
            pytest.fail()

    time.sleep(5)
    enroll_token = ansible_module.shell('tpsclient < {}'.format(enroll_path))

    # Enroll tps token
    for result in enroll_token.values():
        if result['rc'] == 1:
            assert "Result> Success - Operation 'ra_enroll' Success" in result['stdout']
            log.info('Successfully enrolled the token with : {}'.format(result['cmd']))
        else:
            assert result['rc'] > 1
            log.error('Failed to run : {}'.format(result['cmd']))
            pytest.fail(result['stderr'])


@pytest.mark.positive
def test_tpstoken_show_validgroup(ansible_module):
    """
    :Description: Command should successfully show tokens.
    """
    contacted = ansible_module.pki(
        cli='tps-token-show',
        nssdb=constants.NSSDB,
        extra_args='40906145C76224192D2B',
        protocol='http',
        certnick='"PKI TPS Administrator for Example.Org"'
    )
    for result in contacted.values():
        if result['rc'] == 0:
            assert "Token" in result['stdout']
            assert "Token ID" in result['stdout']
            assert "Type" in result['stdout']
            assert "Status" in result['stdout']
        else:
            log.error('Failed to run : {}'.format(result['cmd']))
            pytest.fail(result['stderr'])


@pytest.mark.negative
def test_tpstoken_show_exception(ansible_module):
    """
    :Description: Command should give "ResourceNotFoundException".
    """
    contacted = ansible_module.pki(
        cli='tps-token-show',
        extra_args='40906145C76224192D2BRR',
        certnick='"PKI TPS Administrator for Example.Org"'
    )
    for result in contacted.values():
        if result['rc'] >= 1:
            assert "ResourceNotFoundException: No such object." in result['stderr']
        else:
            log.error('Failed to run : {}'.format(result['cmd']))
            pytest.fail(result['stdout'])


@pytest.mark.positive
@pytest.mark.parametrize("extra_args, certnick", [
    ('40906145C76224192D2B', '"PKI TPS Administrator for Example.Org"'),
])
@pytest.mark.positive
def test_tpstoken_show_help(ansible_module, extra_args, certnick):
    """
    :Description: Command should successfully show tokens.
    """
    contacted = ansible_module.pki(
        cli='tps-token-show',
        extra_args=extra_args,
        protocol='https',
        certnick=certnick
    )
    for result in contacted.values():
        if result['rc'] == 0:
            assert "Token" in result['stdout']
            assert "Token ID" in result['stdout']
            assert "Type" in result['stdout']
            assert "Status" in result['stdout']
        else:
            log.error('Failed to run : {}'.format(result['cmd']))
            pytest.fail(result['stderr'])

