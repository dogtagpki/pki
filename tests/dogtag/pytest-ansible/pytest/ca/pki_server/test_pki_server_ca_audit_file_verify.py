"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI SERVER CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki-server cli commands needs to be tested:
#   pki-server ca-audit-file-find
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Amol Kahat <akahat@redhat.com>
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

import sys

import os
import pytest
import logging

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

TOPOLOGY = int(constants.CA_INSTANCE_NAME.split("-")[-2])
log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)


def test_pki_server_ca_audit_file_verify(ansible_module):
    """
    :id: eb438fc6-befb-48de-bb9e-1fb1d9a48925
    :Title: Test pki-server ca-audit-file-verify command
    :Description: Test pki-server ca-audit-file-verify command
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :Expectedresults:
            1. It should show the error message.
    """
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
    else:
        instance = constants.CA_INSTANCE_NAME
    cmd = 'pki-server ca-audit-file-verify -i {}'.format(instance)
    cmd_out = ansible_module.shell(cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Verification process complete.' in result['stdout']
            assert 'Valid signatures:' in result['stdout']
            assert 'Invalid signatures:' in result['stdout']
        else:
            pytest.fail("Failed to run pki-server ca-audit-file-verify command.")


def test_pki_server_ca_audit_file_verify_with_valid_instance(ansible_module):
    """
    :id: e408ed2b-22a1-4710-a07b-9449107b1ec3
    :Title: Test pki-server ca-audit-file-verify with valid instance.
    :Description: Test pki-server ca-audit-file-verify with valid instance.
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :Expectedresults:
            1. Command should verify the file contents and it's signature.
    """
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
    else:
        instance = constants.CA_INSTANCE_NAME
    cmd = 'pki-server ca-audit-file-verify -i {}'.format(instance)
    cmd_out = ansible_module.shell(cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Verification process complete.' in result['stdout']
            assert 'Valid signatures:' in result['stdout']
            assert 'Invalid signatures:' in result['stdout']
        else:
            pytest.fail("Failed to run pki-server ca-audit-file-verify -"
                         "i {} command".format(instance))


def test_pki_server_ca_audit_file_verify_with_invalid_instance(ansible_module):
    """
    :id: e408ed2b-22a1-4710-a07b-9449107b1ec3
    :Title: Test pki-server ca-audit-file-verify with invalid instance
    :Description: Test pki-server ca-audit-file-verify with invalid instance
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :Expectedresults:
            1. It should throw an error.
    """

    cmd = 'pki-server ca-audit-file-verify -i invalid_instance'
    cmd_out = ansible_module.shell(cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            pytest.fail("Failed to run pki-server ca-audit-file-verify with invalid instance.")
        else:
            assert "ERROR: Invalid instance invalid_instance" in result['stderr']
