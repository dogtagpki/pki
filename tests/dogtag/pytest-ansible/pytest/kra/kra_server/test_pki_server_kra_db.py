"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI-SERVER CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki-server kra-db commands needs to be tested:
#   pki-server kra-db --help
#   pki-server kra-db-vlv --help
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Amol Kahat <akahat@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2019 Red Hat, Inc. All rights reserved.
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
import sys

import pytest

from pki.testlib.common.utils import UserOperations

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

user_op = UserOperations(nssdb=constants.NSSDB)
log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)

TOPOLOGY = constants.CA_INSTANCE_NAME.split("-")[-2]


@pytest.mark.parametrize('args', ['--help', '', 'asdfa'])
def test_pki_server_kra_db_command(ansible_module, args):
    """
    :Title: Test pki-srever kra-db --help command
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement: RHCS-REQ KRA Server CLI Tests
    :ExpectedResults: Verify whether pki-server kra-db --help command shows the following commands.
    Commands:
     kra-db-vlv                    KRA VLV management commands
    """
    server_out = ansible_module.command('pki-server kra-db {}'.format(args))
    for result in server_out.values():
        if result['rc'] == 0:
            assert "kra-db-vlv                    KRA VLV management commands" in result['stdout']
            log.info("Successfully run {}".format(result['cmd']))
        elif args == 'asdfa':
            assert 'ERROR: Invalid module "asdfa"' in result['stderr']
            log.info("Successfully run {}".format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.xfail()


@pytest.mark.parametrize('args', ['--help', '', 'asdfa'])
def test_pki_server_kra_db_vlv_command(ansible_module, args):
    """
    :Title: Test pki-server kra-db-vlv --help command
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement: RHCS-REQ KRA Server CLI Tests
    :ExpectedResults: Verify whether pki-server kra-db-vlv --help command shows the following commands.
        Commands:
         kra-db-vlv-find               Find KRA VLVs
         kra-db-vlv-add                Add KRA VLVs
         kra-db-vlv-del                Delete KRA VLVs
         kra-db-vlv-reindex            Re-index KRA VLVs
    """
    server_out = ansible_module.command('pki-server kra-db-vlv {}'.format(args))
    for result in server_out.values():
        if result['rc'] == 0:
            assert "kra-db-vlv-find               Find KRA VLVs" in result['stdout']
            assert "kra-db-vlv-add                Add KRA VLVs" in result['stdout']
            assert "kra-db-vlv-del                Delete KRA VLVs" in result['stdout']
            assert "kra-db-vlv-reindex            Re-index KRA VLVs" in result['stdout']
            log.info("Successfully run {}".format(result['cmd']))
        elif args == 'asdfa':
            assert 'ERROR: Invalid module "asdfa"' in result['stderr']
            log.info("Successfully run {}".format(result['cmd']))
        else:
            log.error("Failed to run {}".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
