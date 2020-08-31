"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: ca-audit with Role User Sanity Tests
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
from test_steps import ok

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
                           host=constants.MASTER_HOSTNAME,
                           port=constants.CA_HTTP_PORT,
                           nick="'{}'".format(constants.CA_ADMIN_NICK))
    cert_setup.create_certdb(ansible_module)
    cert_setup.import_ca_cert(ansible_module)
    cert_setup.import_admin_p12(ansible_module, 'ca')
    cert_setup.setup_role_users(ansible_module, 'ca', duration='minute')


@pytest.mark.parametrize("certnick,expected", [
    ("CA_AdminV", ['Status: Enabled', 'Signed: true',
                   'Interval (seconds): 5',
                   'Buffer size (bytes): 512']),
    (pytest.param("CA_AdminE", ['FATAL: SSL alert received: CERTIFICATE_EXPIRED'], marks=pytest.mark.xfail)),
    ("CA_AdminR", ['PKIException: Unauthorized'])
])
def test_ca_audit_with_role_users(ansible_module, certnick, expected):
    """
    Test and verify pki ca-audit-show with CA_AdminV
    shows the audit configuration, with CA_AdminE and CA_AdminR
    verify that CLI does not show audit configuration
    :param ansible_module:
    :param certnick:
    :param expected:
    :return:
    """
    contacted = ansible_module.pki(cli='ca-audit-show',
                                   nssdb=constants.NSSDB,
                                   dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                   protocol='https',
                                   certnick=certnick)
    for result in contacted.values():
        for iter in expected:
            if certnick == "CA_AdminV":
                assert iter in result['stdout']
                ok("Certificate: %s, Expected Output: %s , Actual Output : %s" % (certnick, iter, result['stdout']))
            else:
                assert iter in result['stderr']
                ok("Certificate: %s, Expected Output: %s , Actual Output : %s" % (certnick, iter, result['stderr']))
