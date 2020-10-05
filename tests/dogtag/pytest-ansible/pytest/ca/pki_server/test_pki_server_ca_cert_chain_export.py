"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI SERVER  CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki-server cli commands needs to be tested:
#   pki-server ca-cert
#   pki-server ca-cert-chain
#   pki-server ca-cert-chain-export
#   pki-server ca-cert-request
#   pki-server ca-cert-request-find
#   pki-server ca-cert-request-show
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

from pki.testlib.common import utils

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


def test_pki_server_ca_cert(ansible_module):
    """
    :id: 75bb5b8d-f65b-4205-8d96-b39c0983298d
    :Title: Test pki-server ca-cert command
    :Description: Test pki-server ca-cert command
    :Requirement: Pki Server CA
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :ExpectedResults:
        1. Verify whether pki-server ca-cert command shows ca-cert-chain, ca-cert-request commands
    """

    ca_cert_out = ansible_module.shell('pki-server ca-cert')
    for result in ca_cert_out.values():
        if result['rc'] == 0:
            assert "ca-cert-chain                 CA certificate chain " \
                   "management commands" in result['stdout']
            assert "ca-cert-request               CA certificate requests " \
                   "management commands" in result['stdout']
        else:
            pytest.fail("Failed to run pki-server ca-cert command..!!")


def test_pki_server_ca_cert_chain(ansible_module):
    """
    :id: 13cb6d5c-bc67-4912-a7a9-8530ed834fd0
    :Title: Test pki-server ca-cert-chain command
    :Description: Test pki-server ca-cert-chain command
    :Requirement: Pki Server CA
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :ExpectedResults:
            1. Verify whether pki-server ca-cert-chain command shows
                ca-cert-chain-export commands
    """

    output = ansible_module.shell('pki-server ca-cert-chain')

    for result in output.values():
        if result['rc'] == 0:
            assert "ca-cert-chain-export          Export certificate chain" in \
                   result['stdout']
        else:
            pytest.fail("Failed to run pki-server ca-cert-chain command..!!")


def test_pki_server_ca_cert_chain_export_help(ansible_module):
    """
    :id: 635fccb9-828c-4bec-aa91-ad0e0f53dee1
    :Title: Test pki-server ca-cert-chain-export --help command.
    :Description: Test pki-server ca-cert-chain-export --help command.
    :Requirement: Pki Server CA
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :CaseComponent: \-
    :ExpectedResults:
        1. Verify whether pki-server ca-cert-chain-export command exports ca cert chain
    """

    help_out = ansible_module.shell('pki-server ca-cert-chain-export --help')
    for result in help_out.values():
        if result['rc'] == 0:
            assert "-i, --instance <instance ID>       Instance ID " \
                   "(default: pki-tomcat)" in result['stdout']
            assert "--pkcs12-file <path>           PKCS #12 file to store " \
                   "certificates and keys" in result['stdout']
            assert "--pkcs12-password <password>   Password for the " \
                   "PKCS #12 file" in result['stdout']
            assert "--pkcs12-password-file <path>  File containing the " \
                   "PKCS #12 password" in result['stdout']
            assert "-v, --verbose                      Run in verbose mode" \
                   in result['stdout']
            assert "--help                         Show help message" in \
                   result['stdout']
        else:
            pytest.fail("Failed to run pki-server ca-cert-chain-export "
                         "--help command.")


def test_pki_server_ca_cert_chain_export(ansible_module):
    """
    :id:a874013b-4e39-4a1c-aab1-4fd33281e722
    :Title: Test pki-server ca-cert-chain-export export CA Cert Chain Command
    :Description: Test pki-server ca-cert-chain-export export CA cert chain command
    :Requirement: Pki Server CA
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :CaseComponent: \-
    :ExpectedResults:
        1. Verify whether pki-server ca-cert-chain-export command exports
        ca cert chain
    """
    cmd = 'pki-server ca-cert-chain-export -i {} ' \
          '--pkcs12-file /tmp/ca_cert_chain.p12' \
          '--pkcs12-password {}'.format(ca_instance_name,
                                        constants.CLIENT_PKCS12_PASSWORD)
    password = 'pass:{}'.format(constants.CLIENT_PKCS12_PASSWORD)
    openssl_cmd = 'openssl pkcs12 -info -in /tmp/ca_cert_chain.p12 -password {}'
    export_out = ansible_module.shell(cmd)
    for result in export_out.values():
        if result['rc'] == 0:
            assert "Export complete" in result['stdout']
            assert "Deleted certificate" in result['stdout']
            status = ansible_module.stat(path='/tmp/ca_cert_chain.p12')
            for res in status.values():
                if res['stat']['exists']:

                    output = ansible_module.shell(
                        openssl_cmd.format(password))
                    for r1 in output.values():
                        assert "-----BEGIN CERTIFICATE-----" in r1['stdout']
                        assert "-----END CERTIFICATE-----" in r1['stdout']
                else:
                    pytest.fail("Failed to run pki-server "
                                 "ca-cert-chain-export command.")


def test_pki_server_ca_cert_chain_export_password_file(ansible_module):
    """
    :id: 4dd04a92-ace0-46c8-b054-21ce8de895d4
    :Title: Test pki-server ca-cert-chain-export export CA Cert Chain with password file command.
    :Description: Test pki-server ca-cert-chain-export export CA cert chian with password file.
    :CaseComponent: \-
    :Requirement: Pki Server CA
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :ExpectedResults:
        1. Verify whether pki-server ca-cert-chain-export command exports ca cert chain
    """
    chain_export = 'pki-server ca-cert-chain-export -i {} ' \
                   '--pkcs12-file /tmp/ca_cert_chain.p12 ' \
                   '--pkcs12-password-file /tmp/password.txt'.format(ca_instance_name)
    password = 'pass:{}'.format(constants.CLIENT_PKCS12_PASSWORD)
    openssl_cmd = 'openssl pkcs12 -info -in /tmp/ca_cert_chain.p12 -password {}'

    ansible_module.shell("echo '{}' /tmp/password.txt".format(
        constants.CLIENT_PKCS12_PASSWORD))
    export_out = ansible_module.shell(chain_export)
    for result in export_out.values():
        if result['rc'] == 0:
            assert "Export complete" in result['stdout']
            assert "Deleted certificate" in result['stdout']
            status = ansible_module.stat(path='/tmp/ca_cert_chain.p12')
            for res in status.values():
                if res['stat']['exists']:

                    output = ansible_module.shell(
                        openssl_cmd.format(password))
                    for r1 in output.values():
                        assert "-----BEGIN CERTIFICATE-----" in r1['stdout']
                        assert "-----END CERTIFICATE-----" in r1['stdout']
                else:
                    pytest.fail("Failed to run pki-server "
                                 "ca-cert-chain-export command.")


def test_pki_server_ca_cert_chain_export_with_incorrect_db_pass(ansible_module):
    """
    :id: d82dab88-022a-4b3b-b759-6a2f8ba1125f
    :Title: Test pki-server ca-cert-chain-export with incorrect db password
    :Description: Test pki-server ca-cert-chain-export with incorrect db password
    :Requirement: Pki Server CA
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :CaseComponent: \-
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server ca-cert-chain-export command throws error with wrong password
    """

    password = utils.get_random_string(len=8)
    chain_export = 'pki-server ca-cert-chain-export -i {} ' \
                   '--pkcs12-file /tmp/ca_cert_chain.p12 ' \
                   '--pkcs12-password {}'.format(ca_instance_name, password)

    openssl_cmd = 'openssl pkcs12 -info -in /tmp/ca_cert_chain.p12 -password pass:{}'

    ansible_module.shell("echo '{}' /tmp/password.txt".format(
        constants.CLIENT_PKCS12_PASSWORD))
    status = ansible_module.stat(path='/tmp/ca_cert_chain.p12')
    for r1 in status.values():
        if r1['stat']['exists']:
            ansible_module.shell('rm -rf /tmp/ca_cert_chain.p12')
            export_out = ansible_module.shell(chain_export)
            for result in export_out.values():
                if result['rc'] == 0:
                    assert "Export complete" in result['stdout']
                    assert "Deleted certificate" in result['stdout']
                    status = ansible_module.stat(path='/tmp/ca_cert_chain.p12')
                    for res in status.values():
                        if res['stat']['exists']:
                            output = ansible_module.shell(openssl_cmd.format(password))
                            for r1 in output.values():
                                assert "-----BEGIN CERTIFICATE-----" in r1['stdout']
                                assert "-----END CERTIFICATE-----" in r1['stdout']
                        else:
                            pytest.fail("Failed to run pki-server "
                                         "ca-cert-chain-export command.")
