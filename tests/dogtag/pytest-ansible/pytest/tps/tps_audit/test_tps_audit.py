"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI TPS-AUDIT tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki tps commands needs to be tested:
#   pki tps-audit
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Sumedh Sidhaye <ssidhaye@redhat.com>
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
"""

import os
import sys
import pytest
from test_steps import *

from pki.testlib.common.certlib import *

if os.path.isfile('/tmp/test_dir/constants.py'):
    sys.path.append('/tmp/test_dir')
    import constants


@pytest.mark.setup
def test_setup(ansible_module):
    """
    Prerequisites for running pytest-ansible tests
    """
    cert_setup = CertSetup(nssdb=constants.NSSDB,
                           db_pass=constants.CLIENT_DATABASE_PASSWORD,
                           host='pki1.example.com',
                           port=constants.CA_HTTP_PORT,
                           nick="'{}'".format(constants.CA_ADMIN_NICK))
    tps_cert_setup = CertSetup(nssdb=constants.NSSDB,
                               db_pass=constants.CLIENT_DATABASE_PASSWORD,
                               host='pki1.example.com',
                               port=constants.TPS_HTTP_PORT,
                               nick="'{}'".format(constants.TPS_ADMIN_NICK))
    cert_setup.create_certdb(ansible_module)
    cert_setup.import_ca_cert(ansible_module)
    cert_setup.import_admin_p12(ansible_module, 'ca')
    cert_setup.setup_role_users(ansible_module, 'ca', constants.CA_ADMIN_NICK, duration='minute')
    tps_cert_setup.import_admin_p12(ansible_module, 'tps')
    tps_cert_setup.setup_role_users(ansible_module, 'tps', constants.TPS_ADMIN_NICK,
                                    constants.TPS_HTTP_PORT,
                                    constants.CA_ADMIN_NICK, duration='minute')


@pytest.mark.parametrize("helpoutput,expected", [
    ("--help", ["Commands:",
                "tps-audit-mod           Modify audit configuration",
                "tps-audit-show          Show audit configuration",
                "tps-audit-file-find     Find audit files",
                "tps-audit-file-retrieve Retrieve audit file"]),
])
@pytest.mark.ansible(host_pattern='master')
def test_tps_audit_help(ansible_module, helpoutput, expected):
    """
    Test and verify pki tps-audit --help output shows tps-audit sub commands
    :param ansible_module:
    :param helpoutput:
    :param expected:
    :return:
    """
    contacted = ansible_module.command("pki tps-audit --help")
    for result in contacted.values():
        for iter in expected:
            assert iter in result['stdout']


@pytest.mark.parametrize("certnick,expected", [
    ("'PKI TPS Administrator for Example.Org'", ['Audit configuration',
                                                 'Status: Enabled',
                                                 'Signed: true',
                                                 'Interval (seconds): 5',
                                                 'Buffer size (bytes): 512']),
])
def test_tps_audit_with_TPSAdmin(ansible_module, certnick, expected):
    """
    Test and verify pki tps-audit-show with 'PKI TPS Administrator for Example.Org'
    shows the audit configuration
    :param ansible_module:
    :param certnick:
    :param expected:
    :return:
    """
    contacted = ansible_module.pki(
        cli='tps-audit-show',
        nssdb='/opt/pki/certdb',
        protocol='https',
        certnick=certnick
        )
    for result in contacted.values():
        for iter in expected:
            assert iter in result['stdout']


@pytest.mark.parametrize("certnick,expected", [
    ("'PKI CA Administrator for Example.Org'", ["PKIException: Unauthorized"]),
])
def test_tps_audit_with_CAAdmin(ansible_module, certnick, expected):
    """
    Test and verify pki tps-audit-show with 'PKI CA Administrator for Example.Org'
    does not show the audit configuration
    :param ansible_module:
    :param certnick:
    :param expected:
    :return:
    """
    contacted = ansible_module.pki(
        cli='tps-audit-show',
        nssdb='/opt/pki/certdb',
        protocol='https',
        certnick=certnick
        )
    for result in contacted.values():
        for iter in expected:
            assert iter in result['stderr']
