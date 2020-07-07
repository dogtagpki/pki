"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: ca-audit with Role User Sanity Tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Amol Kahat <akahat@redhat.com>
#   Description: kra-audit with Role User Sanity Tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Pritam Singh <prisingh@redhat.com>
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
"""

import logging
import os
import sys

import pytest

from pki.testlib.common.certlib import CertSetup

if os.path.isfile('/tmp/test_dir/constants.py'):
    sys.path.append('/tmp/test_dir')
    import constants

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)


def test_setup_kra_role_users(ansible_module):
    """
    Prerequisites for running pytest-ansible tests
    """
    cert_setup = CertSetup(nssdb=constants.NSSDB,
                           db_pass=constants.CLIENT_DATABASE_PASSWORD,
                           host=constants.MASTER_HOSTNAME,
                           port=constants.KRA_HTTP_PORT,
                           nick="'{}'".format(constants.KRA_ADMIN_NICK))
    try:
        cert_setup.create_certdb(ansible_module)
    except Exception as e:
        print(e)
    cert_setup.import_ca_cert(ansible_module)
    cert_setup.import_admin_p12(ansible_module, 'ca')
    cert_setup.import_admin_p12(ansible_module, 'kra')
    cert_setup.add_expired_profile_to_ca(ansible_module, duration='minute')
    cert_setup.setup_role_users(ansible_module, 'kra', duration='minute')


@pytest.mark.parametrize("certnick,expected", [("KRA_AdminV", ['Status: Enabled', 'Signed: true',
                                                               'Interval (seconds): 5',
                                                               'Buffer size (bytes): 512'])
                                               ])
def test_kra_audit_with_role_users(ansible_module, certnick, expected):
    """
    Test and verify pki kra-audit-show with KRA_AdminV
    shows the audit configuration, with KRA_AdminE and KRA_AdminR
    verify that CLI does not show audit configuration
    :param ansible_module:
    :param certnick:
    :param expected:
    :return:
    """
    contacted = ansible_module.pki(cli='kra-audit-show',
                                   nssdb=constants.NSSDB,
                                   dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                   port=constants.KRA_HTTP_PORT,
                                   hostname=constants.MASTER_HOSTNAME,
                                   certnick='"{}"'.format(certnick))
    for result in contacted.values():
        for iter in expected:
            if certnick == "KRA_AdminV":
                assert iter in result['stdout']
                log.info("Certificate: {}, Expected Output: {} , Actual Output : {}".format(certnick, iter,
                                                                                            result['stdout']))
                log.info("Successfully run: {}".format(result['cmd']))
            else:
                assert iter in result['stderr']
                log.info("Certificate: {}, Expected Output: {} , Actual Output : {}".format(certnick, iter,
                                                                                            result['stderr']))
                log.info("Successfully run: {}".format(result['cmd']))
