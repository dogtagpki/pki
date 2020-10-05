"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI SERVER  CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki-server cli commands needs to be tested:
#   pki-server ca-clone
#   pki-server ca-clone-prepare
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

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants
TOPOLOGY = constants.CA_INSTANCE_NAME.split("-")[-2]

if TOPOLOGY == '01':
    ca_instance_name = 'pki-tomcat'
    topology_name = 'topology-01-CA'
else:
    ca_instance_name = constants.CA_INSTANCE_NAME
    topology_name = constants.CA_INSTANCE_NAME


def test_pki_server_ca_clone(ansible_module):
    """
    :id: d2e47e97-5096-4e56-a856-021a659289a2
    :Title: Test pki-server ca-clone command
    :Requirement: Pki Server CA
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults: 
        1.Verify whether pki-server ca-clone shows ca-clone-prepare command
    """
    clone_out = ansible_module.shell('pki-server ca-clone')
    for result in clone_out.values():
        if result['rc'] == 0:
            assert "ca-clone-prepare              Prepare CA clone" in result['stdout']
        else:
            pytest.fail("Failed to run pki-server ca-clone command.")


def test_pki_server_ca_clone_prepare_help(ansible_module):
    """
    :id: 2720f206-d4ec-4455-bd16-937f6e5611f0
    :Title: Test pki-server ca-clone-prepare --help command
    :Description: Test pki-server ca-clone-prepare --help command
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :CaseComponent: \-
    :Requirement: Pki Server CA
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server ca-clone-prepare --help command shows help option
    """
    help_out = ansible_module.shell('pki-server ca-clone-prepare --help')
    for result in help_out.values():
        if result['rc'] == 0:
            assert "Usage: pki-server ca-clone-prepare [OPTIONS]" in result['stdout']
            assert "-i, --instance <instance ID>       Instance ID (default: pki-tomcat)." in \
                   result['stdout']
            assert "--pkcs12-file <path>           PKCS #12 file to store certificates and keys." \
                   in result['stdout']
            assert "--pkcs12-password <password>   Password for the PKCS #12 file." in \
                   result['stdout']
            assert "--pkcs12-password-file <path>  File containing the PKCS #12 password." in \
                   result['stdout']
            assert "-v, --verbose                      Run in verbose mode." in result['stdout']
            assert "--help                         Show help message." in result['stdout']

        else:
            pytest.fail("Failed to run pki-server ca-clone-prepare --help command..!!")


def test_pki_server_ca_clone_prepare(ansible_module):
    """
    :id: 63d0c7fe-bb25-4f33-9929-4eb2f24c60d9
    :Title: Test pki-server ca-clone-prepare command
    :Description: Test pki-server ca-clone-prepare command
    :Requirement: Pki Server CA
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server ca-clone-prepare command exports ca backup keys
    """
    cmd = 'pki-server ca-clone-prepare -i {} --pkcs12-file /tmp/ca_backup_keys.p12 ' \
          '--pkcs12-password {}'.format(ca_instance_name, constants.CLIENT_PKCS12_PASSWORD)
    export_out = ansible_module.shell(cmd)
    for result in export_out.values():
        if result['rc'] == 0:
            assert "Imported certificate" in result['stdout']
            isfile = ansible_module.stat(path='/tmp/ca_backup_keys.p12')
            for res in isfile.values():
                assert res['stat']['exists']
        else:
            pytest.fail("Failed to run pki-server ca-clone-prepare command..!!")
    ansible_module.shell('rm -rf /tmp/ca_backup_keys.p12')


def test_pki_server_ca_clone_prepare_password_file(ansible_module):
    """
    :id: 4f2cc61a-7167-4781-b8f1-5898b30d6bca
    :Title: Test pki-server ca-clone-prepare command.
    :Description: Test pki-server ca-clone-prepare command
    :Requirement: Pki Server CA
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server ca-clone-prepare command with password file
           exports ca backup keys.
    """
    cmd = 'pki-server ca-clone-prepare -i {} --pkcs12-file /tmp/ca_backup_keys.p12 ' \
          '--pkcs12-password-file /tmp/password.txt'.format(ca_instance_name, constants.CLIENT_PKCS12_PASSWORD)
    ansible_module.shell("echo '{}' > /tmp/password.txt".format(constants.CLIENT_PKCS12_PASSWORD))
    status = ansible_module.stat(path='/tmp/ca_backup_keys.p12')
    export_out = ansible_module.shell(cmd)
    for result in export_out.values():
        if result['rc'] == 0:
            assert "Imported certificate" in result['stdout']
            isfile = ansible_module.stat(path='/tmp/ca_backup_keys.p12')
            for res in isfile.values():
                assert res['stat']['exists']
        else:
            pytest.fail("Failed to run pki-server ca-clone-prepare command.")
    ansible_module.shell('rm -rf /tmp/ca_backup_keys.p12')
