"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki-server subsystem cli commands needs to be tested:
#   pki-server subsystem-cert-update
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
import re

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants


@pytest.mark.xfail(reason='BZ-1340718')
def test_pki_server_subsystem_cert_update_help(ansible_module):
    """
    :id: 39e76a9d-ddec-4d64-aa14-dfe123bad278
    :Title: Test pki-server subsystem-cert-udpate --help command
    :Description: test pki-server subsystem-cert-update --help command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :Expectedresults: 
        1. Verify whether pki-server subsystem-cert-update --help command shows help options.
    """

    cert_update_help = ansible_module.command('pki-server subsystem-cert-update --help')
    for result in cert_update_help.values():
        if result['rc'] == 0:
            assert "Usage: pki-server subsystem-cert-update [OPTIONS] <subsystem ID> <cert ID>" \
                   in result['stdout']
            assert "-i, --instance <instance ID>    Instance ID (default: pki-tomcat)." in \
                   result['stdout']
            assert "-v, --verbose                   Run in verbose mode." in \
                   result['stdout']
            assert "--help                      Show help message." in result['stdout']
            assert "--cert <certificate>        New certificate to be added" in \
                   result['stdout']
        else:
            pytest.xfail("Failed to run pki-server subsystem-cert-update --help command.")


@pytest.mark.xfail(reason='BZ-1340455')
def test_pki_server_subsystem_cert_update(ansible_module):
    """
    :id: e990a3bb-88c2-45d1-a4d3-b7b0015bf40c
    :Title: Test pki-server subsystem-cert-update command
    :Description: test pki-server subsystem-cert-update command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :Expectedresults:
        1. Verify whether pki-server subsystem-cert-update command updates the certificate.
    """
    cert_update = ansible_module.command('pki-server subsystem-cert-update '
                                         '-i {} ca signing'.format(constants.CA_INSTANCE_NAME))
    for result in cert_update.values():
        if result['rc'] == 0:
            assert 'Updated "signing" subsystem certificate' in result['stdout']
        else:
            pytest.xfail("Failed to run pki-server subsystem-cert-update command.")


def test_pki_server_subsystem_cert_update_with_CA_instance(ansible_module):
    """
    :id: 89d27adf-9089-4a2e-bb7e-b8b9325c613a
    :Title: Test pki-server subsystem-cert-update with CA certificate.
    :Description: This test case will update the existing certificate with new certificate.
    :Requirement: Pki Server Subsystem
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Create certificate renew request: pki client-cert-request --serial <serial> --renewal
        2. Approve the certificate request
        3. Get the certificate in to the database and export it to the pem file.
        4. Update the certificate: pki-server subsystem-cert-update ca <cert_id> --cert cert.pem
    :ExpectedResults:
        1.  Certificate should get updated in to the database.
    """
    request_id = None
    certificate_id = None
    new_subsystem_cert = '/tmp/certificate_{}.pem'
    subject = "CN=CA Subsystem Certificate,OU={},O={}".format(constants.CA_INSTANCE_NAME,
                                                              constants.CA_SECURITY_DOMAIN_NAME)

    client_cert_request = 'pki -d {} -c {} -p {} -P https client-cert-request ' \
                          '--profile caSubsystemCert ' \
                          ' "{}"'.format(constants.NSSDB, constants.CLIENT_DIR_PASSWORD,
                                         constants.CA_HTTPS_PORT, subject)

    create_req = ansible_module.command(client_cert_request)
    for result in create_req.values():
        if result['rc'] == 0:
            stdout = re.findall('Request ID: [\w].*', result['stdout'])
            request_id = stdout[0].split(":")[1].strip()
        else:
            pytest.xfail("Failed to create certificate request.")
    if request_id:
        cert_request_review = 'pki -d {} -c {} -p {} -P https -n "{}" ca-cert-request-review {} ' \
                              '--action approve'.format(constants.NSSDB,
                                                        constants.CLIENT_DIR_PASSWORD,
                                                        constants.CA_HTTPS_PORT,
                                                        constants.CA_ADMIN_NICK, request_id)
        review = ansible_module.command(cert_request_review)
        for result in review.values():
            if result['rc'] == 0:
                stdout = re.findall('Certificate ID: [\w].*', result['stdout'])
                certificate_id = stdout[0].split(":")[1].strip()
                new_subsystem_cert = new_subsystem_cert.format(certificate_id)
                ansible_module.command('pki -d {} -c {} -p {} client-cert-import '
                                       '"Subsystem Cert" '
                                       '--serial {}'.format(constants.NSSDB,
                                                            constants.CLIENT_DIR_PASSWORD,
                                                            constants.CA_HTTP_PORT,
                                                            certificate_id))

                ansible_module.command('pki -d {} -c {} client-cert-show --cert {} '
                                       '"Subsystem Cert"'.format(constants.NSSDB,
                                                                 constants.CLIENT_DIR_PASSWORD,
                                                                 new_subsystem_cert))
    if certificate_id:
        cert_update = ansible_module.command('pki-server subsystem-cert-update ca subsystem -i {} '
                                             '--cert {}'.format(constants.CA_INSTANCE_NAME,
                                                                new_subsystem_cert))
        for result in cert_update.values():
            if result['rc'] == 0:
                assert 'Updated "subsystem" subsystem certificate' in result['stdout']
                ansible_module.command('systemctl restart pki-tomcatd@{}'.format(
                    constants.CA_INSTANCE_NAME))
                is_active = ansible_module.command('systemctl is-active pki-tomcatd@{}'.format(
                    constants.CA_INSTANCE_NAME))
                for res in is_active.values():
                    if res['rc'] == 0:
                        assert 'active' in res['stdout']
                    else:
                        pytest.xfail("Failed to restart the server.")


def test_pki_server_subsystem_cert_update_with_invalid_instance(ansible_module):
    """
    :id: 9fa1a364-8477-4997-bdae-95ec255b8df0
    :Title: Test pki server subsystem cert update with invalid instance.
    :Description:  Test pki server subsytem cert update with invalid instance.
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
    """
    ansible_module.command('pki -p {} -P https cert-show 0x2 --encoded '
                           '--output /tmp/certificate_0x2.pem')
    pki_subsystem_cmd = 'pki-server subsystem-cert-update  ca ocsp_signing -i  invalid_instance ' \
                        '--cert /tmp/certificate_0x2.pem'
    cmd_out = ansible_module.command(pki_subsystem_cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            pytest.xfail("Failed to run pki-server subsystem cert command with "
                         "invalid instance.")
        else:
            assert "ERROR: Invalid instance invalid_instance" in result['stdout']


def test_pki_server_subsystem_cert_update_without_subsystem_id(ansible_module):
    """
    :id: 18ddae4c-76d8-4606-a715-28ee363e298e
    :Title: Test pki server subsystem cert update without subsystem id.
    :Description:  Test pki server subsytem cert update without subsystem id.
    :Requirement: Pki Server Subsystem
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
    """
    ansible_module.command('pki -p {} -P https cert-show 0x2 --encoded '
                           '--output /tmp/certificate_0x2.pem')
    pki_subsystem_cmd = 'pki-server subsystem-cert-update  ocsp_signing -i  invalid_instance ' \
                        '--cert /tmp/certificate_0x2.pem'
    cmd_out = ansible_module.command(pki_subsystem_cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            pytest.xfail("Failed to run pki-server subsystem cert command with "
                         "invalid instance.")
        else:
            assert "ERROR: missing cert ID" in result['stdout']


def test_pki_server_subsystem_cert_update_without_cert_id(ansible_module):
    """
    :id: 61ad9a42-ad5d-42f9-98ca-72943d5e77aa
    :Title: Test pki server subsystem cert update without cert id.
    :Description: This test should fail if cert id is not provided.
    :Requirement: Pki Server Subsystem
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
    """
    ansible_module.command('pki -p {} -P https cert-show 0x2 --encoded '
                           '--output /tmp/certificate_0x2.pem')
    pki_subsystem_cmd = 'pki-server subsystem-cert-update ca -i  invalid_instance ' \
                        '--cert /tmp/certificate_0x2.pem'
    cmd_out = ansible_module.command(pki_subsystem_cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            pytest.xfail("Failed to run pki-server subsystem cert command with "
                         "invalid instance.")
        else:
            assert "ERROR: missing cert ID" in result['stdout']


def test_pki_server_subsystem_cert_update_invalid_subsystem_id(ansible_module):
    """
    :id: c9036c14-0510-4e34-9785-a0e9e9f41a6c
    :Title: Test pki server subsystem cert update with invalid subsystem id.
    :Description: This test should fail if subsystem id is invalid.
    :Requirement: Pki Server Subsystem
    :CaseComponent: \-
    :Type:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
    """
    ansible_module.command('pki -p {} -P https cert-show 0x2 --encoded '
                           '--output /tmp/certificate_0x2.pem')
    pki_subsystem_cmd = 'pki-server subsystem-cert-update not_exists ocsp_signing ' \
                        '-i  {} --cert /tmp/certificate_0x2.pem'.format(constants.CA_INSTANCE_NAME)
    cmd_out = ansible_module.command(pki_subsystem_cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            pytest.xfail("Failed to run pki-server subsystem cert command with "
                         "invalid instance.")
        else:
            assert "ERROR: No not_exists subsystem in " \
                   "instance {}.".format(constants.CA_INSTANCE_NAME) in result['stdout']


def test_pki_server_subsystem_cert_update_when_file_does_not_exists(ansible_module):
    """
    :id: 50d80688-46bd-4af6-9084-9117b25702e5
    :Title: Test pki server subsystem cert update when file does not exists.
    :Description: This test should fail if file does not exists.
    :Requirement: Pki Server Subsystem
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
    """
    pki_subsystem_cmd = 'pki-server subsystem-cert-update ca ocsp_signing -i {} ' \
                        '--cert /tmp/dosjf.pem'.format(constants.CA_INSTANCE_NAME)

    pki_subsystem_out = ansible_module.command(pki_subsystem_cmd)
    for result in pki_subsystem_out.values():
        if result['rc'] == 0:
            pytest.xfail("Failed to run pki-server subsystem cert command when cert file does "
                         "not exists.")
        else:
            assert "ERROR: /tmp/dosjf.pem certificate does not exist." in result['stdout']
