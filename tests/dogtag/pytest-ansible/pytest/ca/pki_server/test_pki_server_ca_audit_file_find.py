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

def test_pki_server_ca_audit_file_find_command(ansible_module):
    """
    :id: 521fa257-a75a-43ba-9689-03ec4f82f0d0
    :Title: Test pki-server ca-audit-file-find command.
    :Description: Test pki-server ca-audit-file-find command.
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki-server ca-audit-file-find
    :Expectedresults:
        1. It should show the error message.
    """
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
    else:
        instance = constants.CA_INSTANCE_NAME
    cmd = 'pki-server ca-audit-file-find -i {}'.format(instance)
    cmd_out = ansible_module.shell(cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'File name:' in result['stdout']
        else:
            pytest.fail("Failed to run pki-server ca-audit-file-find.")


def test_pki_server_ca_audit_file_find_with_help_option(ansible_module):
    """
    :id: d7eb1fde-70d0-4586-90bc-c6cae31fc9ec
    :Title: Test pki-server ca-audit-file-find with --help option.
    :Description: Test pki-server ca-audit-file-find with --help option.
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki-server ca-audit-file-find --help
    :Expectedresults:
        1. It should show the help options.
    """

    cmd = 'pki-server ca-audit-file-find --help'
    cmd_out = ansible_module.shell(cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Usage: pki-server ca-audit-file-find [OPTIONS]' in result['stdout']
            assert '-i, --instance <instance ID>       Instance ID (default: pki-tomcat).' in \
                   result['stdout']
            assert '-v, --verbose                      Run in verbose mode.' in result['stdout']
            assert '--help                         Show help message.' in result['stdout']
        else:
            pytest.fail("Failed to run pki-server ca-audit-file-find --help command.")


def test_pki_server_ca_audit_file_find_with_valid_instance(ansible_module):
    """
    :id: c0d88e24-cefe-4176-87a7-c0cf5119caea
    :Title: Test pki-server ca-audit-file-find with valid instance.
    :Description: Test pki-server ca-audit-file-find with valid instance.
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki-server ca-audit-file-find -i <instance>
    :Expectedresults:
        1. It should show the audit file.
    """
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
    else:
        instance = constants.CA_INSTANCE_NAME
    cmd = 'pki-server ca-audit-file-find -i {}'.format(instance)
    cmd_out = ansible_module.shell(cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'entries matched' in result['stdout']
            assert 'File name:' in result['stdout']
        else:
            pytest.fail("Failed to run pki-server ca-audit-file-find "
                         "-i {} command".format(instance))


def test_pki_server_ca_audit_file_find_with_invalid_instance(ansible_module):
    """
    :id: 8201bd38-79b6-4994-8bfb-c0f4c62733d0
    :Title: Test pki-server ca-audit-file-find with invalid instance.
    :Description: Test pki-server ca-audit-file-find with invalid instance.
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki-server ca-audit-file-find -i invalid_instance
    :Expectedresults:
        1. It should show the error message.
    """

    cmd = 'pki-server ca-audit-file-find -i invalid_instance'
    cmd_out = ansible_module.shell(cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'entries matched' in result['stdout']
            assert 'File name:' in result['stdout']
            pytest.fail("Failed to run pki-server ca-audit-file-find -i invalid_instance command")
        else:
            assert 'ERROR: Invalid instance invalid_instance' in result['stderr']
