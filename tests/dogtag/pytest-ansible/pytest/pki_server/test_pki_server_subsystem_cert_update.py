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
TOPOLOGY = int(constants.CA_INSTANCE_NAME.split("-")[-2])
log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
userop = UserOperations(nssdb=constants.NSSDB)


# @pytest.mark.xfail(reason='BZ-1340718')
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
            assert "Usage: pki-server subsystem-cert-update [OPTIONS] <subsystem ID> <cert ID>" in result['stdout']
            assert "-i, --instance <instance ID>    Instance ID (default: pki-tomcat)." in result['stdout']
            assert "-v, --verbose                   Run in verbose mode." in result['stdout']
            assert "--help                      Show help message." in result['stdout']
            assert "--cert <certificate>        New certificate to be added" in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.info("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()


# @pytest.mark.xfail(reason='BZ-1340455')
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
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
        security_domain = constants.CA_SECURITY_DOMAIN_NAME
    else:
        instance = constants.CA_INSTANCE_NAME
        security_domain = constants.CA_SECURITY_DOMAIN_NAME
    cert_update = ansible_module.command('pki-server subsystem-cert-update '
                                         '-i {} ca signing'.format(instance))
    for result in cert_update.values():
        if result['rc'] == 0:
            assert 'Updated "signing" subsystem certificate' in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.info("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()


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
    cert = _id = None
    profile = 'caSubsystemCert'
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
        security_domain = constants.CA_SECURITY_DOMAIN_NAME
    else:
        instance = constants.CA_INSTANCE_NAME
        security_domain = constants.CA_SECURITY_DOMAIN_NAME
    alias_dir = '/var/lib/pki/{}/alias'.format(instance)
    subject = "CN=CA Subsystem Certificate,OU={},O={}".format(instance, security_domain)

    internal = ansible_module.shell('grep internal= /var/lib/pki/{}/conf/password.conf'.format(instance))
    internal_pass = [res['stdout'] for res in internal.values()][0].split("=")[1]
    userop = UserOperations(nssdb=alias_dir, db_pass="'{}'".format(internal_pass))
    request_id = userop.create_certificate_request(ansible_module, subject=subject, request_type='pkcs10', algo='rsa',
                                                   keysize='2048', profile=profile)
    userop1 = UserOperations(nssdb=constants.NSSDB)
    cert_id = userop1.process_certificate_request(ansible_module, request_id=request_id, action='approve')

    if cert_id:
        new_subsystem_cert = '/tmp/certificate_{}.pem'.format(cert_id)
        log.info("Certificate generated: {} Subject: {}".format(cert_id, subject))
        ansible_module.command('pki -P http -p {} ca-cert-show {} '
                               '--output {}'.format(constants.CA_HTTP_PORT, cert_id, new_subsystem_cert))

        cert_update = ansible_module.command('pki-server subsystem-cert-update ca subsystem -i {} '
                                             '--cert {}'.format(instance, new_subsystem_cert))
        for result in cert_update.values():
            if result['rc'] == 0:
                assert 'Updated "subsystem" subsystem certificate' in result['stdout']
                log.info("Updated the subsystem certificate.")
                ansible_module.command('systemctl restart pki-tomcatd@{}'.format(instance))
                is_active = ansible_module.command('systemctl is-active pki-tomcatd@{}'.format(instance))
                for res in is_active.values():
                    if res['rc'] == 0:
                        assert 'active' in res['stdout']
                        log.info("Server up successfully.")
                    else:
                        log.error("Failed to restart the server.")
                        pytest.skip()
            else:
                log.error("Failed to run: {}".format(" ".join(result['cmd'])))
                pytest.skip()
    else:
        log.error("Failed to generate the certificate")
        pytest.skip()


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
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
        security_domain = constants.CA_SECURITY_DOMAIN_NAME
    else:
        instance = constants.CA_INSTANCE_NAME
        security_domain = constants.CA_SECURITY_DOMAIN_NAME
    ansible_module.command('pki -p {} cert-show 0x2 --encoded --output '
                           '/tmp/certificate_0x2.pem'.format(constants.CA_HTTP_PORT))
    pki_subsystem_cmd = 'pki-server subsystem-cert-update  ca ocsp_signing -i  invalid_instance ' \
                        '--cert /tmp/certificate_0x2.pem'
    cmd_out = ansible_module.command(pki_subsystem_cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()
        else:
            assert "ERROR: Invalid instance invalid_instance" in result['stderr']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))


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
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
        security_domain = constants.CA_SECURITY_DOMAIN_NAME
    else:
        instance = constants.CA_INSTANCE_NAME
        security_domain = constants.CA_SECURITY_DOMAIN_NAME
    ansible_module.command('pki -p {} cert-show 0x2 --encoded --output '
                           '/tmp/certificate_0x2.pem'.format(constants.CA_HTTP_PORT))
    pki_subsystem_cmd = 'pki-server subsystem-cert-update  ocsp_signing -i {} ' \
                        '--cert /tmp/certificate_0x2.pem'.format(instance)
    cmd_out = ansible_module.command(pki_subsystem_cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()
        else:
            assert "ERROR: Missing cert ID" in result['stderr']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))


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
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
        security_domain = constants.CA_SECURITY_DOMAIN_NAME
    else:
        instance = constants.CA_INSTANCE_NAME
        security_domain = constants.CA_SECURITY_DOMAIN_NAME
    ansible_module.command('pki -P http -p {} cert-show 0x2 --encoded --output '
                           '/tmp/certificate_0x2.pem'.format(constants.CA_HTTP_PORT))
    pki_subsystem_cmd = 'pki-server subsystem-cert-update ca -i {} ' \
                        '--cert /tmp/certificate_0x2.pem'.format(instance)
    cmd_out = ansible_module.command(pki_subsystem_cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()
        else:
            assert "ERROR: Missing cert ID" in result['stderr']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))


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
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
        security_domain = constants.CA_SECURITY_DOMAIN_NAME
    else:
        instance = constants.CA_INSTANCE_NAME
        security_domain = constants.CA_SECURITY_DOMAIN_NAME
    ansible_module.command('pki -P http -p {} cert-show 0x2 --encoded --output '
                           '/tmp/certificate_0x2.pem'.format(constants.CA_HTTP_PORT))
    pki_subsystem_cmd = 'pki-server subsystem-cert-update not_exists ocsp_signing ' \
                        '-i  {} --cert /tmp/certificate_0x2.pem'.format(instance)
    cmd_out = ansible_module.command(pki_subsystem_cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()
        else:
            assert "ERROR: No not_exists subsystem in " \
                   "instance {}.".format(instance) in result['stderr']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))


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
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
        security_domain = constants.CA_SECURITY_DOMAIN_NAME
    else:
        instance = constants.CA_INSTANCE_NAME
        security_domain = constants.CA_SECURITY_DOMAIN_NAME
    pki_subsystem_cmd = 'pki-server subsystem-cert-update ca ocsp_signing -i {} ' \
                        '--cert /tmp/dosjf.pem'.format(instance)

    pki_subsystem_out = ansible_module.command(pki_subsystem_cmd)
    for result in pki_subsystem_out.values():
        if result['rc'] == 0:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()
        else:
            assert "ERROR: /tmp/dosjf.pem certificate does not exist." in result['stderr']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
