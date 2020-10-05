"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki-server subsystem cli commands needs to be tested:
#   pki-server subsystem-cert-validate
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Amol Kahat <akaht@redhat.com>
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
import random
import string
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
def test_pki_server_subsystem_cert_validate_help(ansible_module):
    """
    :id: 210358d0-9a7d-4678-8440-0c125e694a5a
    :Title: Test pki-server subsystem-cert-validate --help command
    :Description: test pki-server subsystem-cert-validate --help command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server subsystem-cert-validate --help command shows help options.
    """
    signing_out = ansible_module.command('pki-server subsystem-cert-validate --help')
    for result in signing_out.values():
        if result['rc'] == 0:
            assert "Usage: pki-server subsystem-cert-validate [OPTIONS] <subsystem ID> [" \
                   "<cert_id>]" in result['stdout']
            assert "-i, --instance <instance ID>    Instance ID (default: pki-tomcat)." in \
                   result['stdout']
            assert "-v, --verbose                   Run in verbose mode." in result['stdout']
            assert "--help                      Show help message." in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run pki-server subsystem-cert-validate --help command.")
            pytest.skip()


@pytest.mark.parametrize('cert_id,nick', (['signing', 'caSigningCert cert-{} CA'],
                                          ['ocsp_signing', 'ocspSigningCert cert-{} CA'],
                                          ['sslserver', 'Server-Cert cert-{}'],
                                          ['subsystem', 'subsystemCert cert-{}'],
                                          ['audit_signing', 'auditSigningCert cert-{} CA']))
def test_pki_server_subsystem_cert_validate_ca_certs(ansible_module, cert_id, nick):
    """
    :id: 230008fd-a5fe-4dee-809b-408e47fd6429
    :Title: Test pki-server subsystem-cert-validate CA Signing certificate
    :Description: test pki-server subsystem-cert-validate command
    :Requirement: Pki Server Subsystem
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server subsystem-cert-validate command validates the
        signing certificate.
    """
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
        security_domain = constants.CA_SECURITY_DOMAIN_NAME
    else:
        instance = constants.CA_INSTANCE_NAME
        security_domain = constants.CA_SECURITY_DOMAIN_NAME
    signing_out = ansible_module.command('pki-server subsystem-cert-validate -i {} ca {}'.format(instance, cert_id))
    for result in signing_out.values():
        if result['rc'] == 0:
            assert "Cert ID: {}".format(cert_id) in result['stdout']
            assert "Nickname: {}".format(nick.format(instance)) in result['stdout']
            assert "Usage:" in result['stdout']
            assert "Token: internal" in result['stdout']
            assert "Status: VALID" in result['stdout']
            log.info("Validate certificate : {}".format(cert_id))
            log.info("Validate certificate Nick : {}".format(nick.format(instance)))
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run {}.".format(" ".join(result['cmd'])))
            pytest.skip()


@pytest.mark.parametrize('cert_id,nick', (['transport', 'transportCert cert-{} KRA'],
                                          ['storage', 'storageCert cert-{} KRA'],
                                          ['sslserver', 'Server-Cert cert-{}'],
                                          ['subsystem', 'subsystemCert cert-{}'],
                                          ['audit_signing', 'auditSigningCert cert-{} KRA']))
def test_pki_server_subsystem_cert_validate_kra_certs(ansible_module, cert_id, nick):
    """
    :id: 1dd9f42a-5fe0-47f4-a497-930b722e35c9
    :Title: Test pki-server subsystem-cert-validate KRA Transport certificate
    :Description: test pki-server subsystem-cert-validate command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server subsystem-cert-validate command validates the kra
        transport certificate.
    """
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
        security_domain = constants.CA_SECURITY_DOMAIN_NAME
    else:
        instance = constants.KRA_INSTANCE_NAME
        security_domain = constants.CA_SECURITY_DOMAIN_NAME
    cert_out = ansible_module.command('pki-server subsystem-cert-validate -i {} kra {}'.format(instance, cert_id))
    for result in cert_out.values():

        if result['rc'] == 0:
            assert "Cert ID: {}".format(cert_id) in result['stdout']
            assert "Nickname: {}".format(nick.format(instance)) in result['stdout']
            assert "Usage:" in result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            assert "Status: VALID" in result['stdout']
            log.info("Validate certificate : {}".format(cert_id))
            log.info("Validate certificate Nick : {}".format(nick.format(instance)))
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run {}.".format(" ".join(result['cmd'])))
            pytest.skip()



@pytest.mark.parametrize('cert_id,nick', (['signing', 'ocspSigningCert cert-{} OCSP'],
                                          ['sslserver', 'Server-Cert cert-{}'],
                                          ['subsystem', 'subsystemCert cert-{}'],
                                          ['audit_signing', 'auditSigningCert cert-{} OCSP']))
def test_pki_server_subsystem_cert_validate_ocsp_certs(ansible_module, cert_id, nick):
    """
    :id: 9a4de285-fe51-45b0-a4fd-3b858a71b2f9
    :Title: Test pki-server subsystem-cert-validate OCSP Signing certificate
    :Description: test pki-server subsystem-cert-validate command
    :Requirement: Pki Server Subsystem
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server subsystem-cert-validate command validates the OCSP
        signing certificate.
    """
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
        security_domain = constants.CA_SECURITY_DOMAIN_NAME
    else:
        instance = constants.OCSP_INSTANCE_NAME
        security_domain = constants.CA_SECURITY_DOMAIN_NAME
    cert_out = ansible_module.command('pki-server subsystem-cert-validate'
                                      ' -i {} ocsp {}'.format(instance, cert_id))
    for result in cert_out.values():
        if result['rc'] == 0:
            assert "Cert ID: {}".format(cert_id) in result['stdout']
            assert "Nickname: {}".format(nick.format(instance)) in result['stdout']
            assert "Usage:" in result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            assert "Status: VALID" in result['stdout']
            log.info("Validate certificate : {}".format(cert_id))
            log.info("Validate certificate Nick : {}".format(nick.format(instance)))
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run {}.".format(" ".join(result['cmd'])))
            pytest.skip()



@pytest.mark.parametrize('cert_id,nick', (['sslserver', 'Server-Cert cert-{}'],
                                          ['subsystem', 'subsystemCert cert-{}'],
                                          ['audit_signing', 'auditSigningCert cert-{} TKS']))
def test_pki_server_subsystem_cert_validate_tks_certs(ansible_module, cert_id, nick):
    """
    :id: 2aa1e537-52a5-48ce-b3fc-a67e4cc9cbb1
    :Title: Test pki-server subsystem-cert-validate TKS SSL Server certificate
    :Description: test pki-server subsystem-cert-validate command
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement: Pki Server Subsystem
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server subsystem-cert-validate command validates the tks
        sslserver certificate.
    """
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
        security_domain = constants.CA_SECURITY_DOMAIN_NAME
    else:
        instance = constants.TKS_INSTANCE_NAME
        security_domain = constants.CA_SECURITY_DOMAIN_NAME
    cert_out = ansible_module.command('pki-server subsystem-cert-validate  -i {} tks {}'.format(instance, cert_id))
    for result in cert_out.values():
        if result['rc'] == 0:
            assert "Cert ID: {}".format(cert_id) in result['stdout']
            assert "Nickname: {}".format(nick.format(instance)) in result['stdout']
            assert "Usage:" in result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            assert "Status: VALID" in result['stdout']
            log.info("Validate certificate : {}".format(cert_id))
            log.info("Validate certificate Nick : {}".format(nick.format(instance)))
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run {}.".format(" ".join(result['cmd'])))
            pytest.skip()



@pytest.mark.parametrize('cert_id,nick', (['sslserver', 'Server-Cert cert-{}'],
                                          ['subsystem', 'subsystemCert cert-{}'],
                                          ['audit_signing', 'auditSigningCert cert-{} TPS']))
def test_pki_server_subsystem_cert_validate_tps_certs(ansible_module, cert_id, nick):
    """
    :id: b22b93d1-fe4d-489d-a121-b0315e1f234f
    :Title: Test pki-server subsystem-cert-validate TPS SSL Server certificate
    :Description: test pki-server subsystem-cert-validate command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server subsystem-cert-validate command validates the tps sslserver
        certificate.
    """
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
        security_domain = constants.CA_SECURITY_DOMAIN_NAME
    else:
        instance = constants.TPS_INSTANCE_NAME
        security_domain = constants.CA_SECURITY_DOMAIN_NAME
    cert_out = ansible_module.command('pki-server subsystem-cert-validate  -i {} tps {}'.format(instance, cert_id))
    for result in cert_out.values():
        if result['rc'] == 0:
            assert "Cert ID: {}".format(cert_id) in result['stdout']
            assert "Nickname: {}".format(nick.format(instance)) in result['stdout']
            assert "Usage:" in result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            assert "Status: VALID" in result['stdout']
            log.info("Validate certificate : {}".format(cert_id))
            log.info("Validate certificate Nick : {}".format(nick.format(instance)))
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run {}.".format(" ".join(result['cmd'])))
            pytest.skip()


@pytest.mark.skipif("TOPOLOGY <= 3")
@pytest.mark.parametrize('cert_id,nick', (['signing', 'caSigningCert cert-{} CA'],
                                          ['ocsp_signing', 'ocspSigningCert cert-{} CA'],
                                          ['sslserver', 'Server-Cert cert-{}'],
                                          ['subsystem', 'subsystemCert cert-{}'],
                                          ['audit_signing', 'auditSigningCert cert-{} CA']))
def test_pki_server_subsystem_cert_validate_ca_clone_certs(ansible_module, cert_id, nick):
    """
    :id: 04ab4e2f-85ab-4698-88be-5eee41645044
    :Title: Test pki-server subsystemc-ert-validate CA Clone Signing certificate
    :Description: test pki-server subsystem-cert-validate command
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Steps:
    :ExpectedResults: 
        1. Verify whether pki-server subsystem-cert-validate command validates the Clone ca
            signing certificate.
    """
    cert_out = ansible_module.command('pki-server subsystem-cert-validate'
                                      ' -i {} ca {}'.format(constants.CLONECA1_INSTANCE_NAME,
                                                            cert_id))
    for result in cert_out.values():
        if result['rc'] == 0:
            assert "Cert ID: {}".format(cert_id) in result['stdout']
            assert "Nickname: {}".format(nick.format(constants.CLONECA1_INSTANCE_NAME)) in \
                   result['stdout']
            assert "Usage:" in result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            assert "Status: VALID" in result['stdout']
            log.info("Validate certificate : {}".format(cert_id))
            log.info("Validate certificate Nick : {}".format(nick.format(constants.CLONECA1_INSTANCE_NAME)))
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run {}.".format(" ".join(result['cmd'])))
            pytest.skip()


@pytest.mark.skipif("TOPOLOGY <= 3")
@pytest.mark.parametrize('cert_id,nick', (['transport', 'transportCert cert-{} KRA'],
                                          ['storage', 'storageCert cert-{} KRA'],
                                          ['sslserver', 'Server-Cert cert-{}'],
                                          ['subsystem', 'subsystemCert cert-{}'],
                                          ['audit_signing', 'auditSigningCert cert-{} KRA']))
def test_pki_server_subsystem_cert_validate_kra_clone_certs(ansible_module, cert_id, nick):
    """
    :id: e7938f86-bbd6-46a8-83da-dfef5c559e2b
    :Title: Test pki-server subsystem-cert-validate KRA Clone Transport certificate
    :Description: test pki-server subsystem-cert-validate command
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Steps:
    :ExpectedResults: 
        1. Verify whether pki-server subsystem-cert-validate command validates the clone kra 
        transport certificate.
    """
    cert_out = ansible_module.command('pki-server subsystem-cert-validate'
                                      ' -i {} kra {}'.format(constants.CLONEKRA1_INSTANCE_NAME,
                                                             cert_id))
    for result in cert_out.values():
        if result['rc'] == 0:
            assert "Cert ID: {}".format(cert_id) in result['stdout']
            assert "Nickname: {}".format(nick.format(constants.CLONEKRA1_INSTANCE_NAME)) in \
                   result['stdout']
            assert "Usage:" in result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            assert "Status: VALID" in result['stdout']
            log.info("Validate certificate : {}".format(cert_id))
            log.info("Validate certificate Nick : {}".format(nick.format(constants.CLONEKRA1_INSTANCE_NAME)))
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run {}.".format(" ".join(result['cmd'])))
            pytest.skip()


@pytest.mark.skipif("TOPOLOGY <= 3")
@pytest.mark.parametrize('cert_id,nick', (['signing', 'ocspSigningCert cert-{} OCSP'],
                                          ['sslserver', 'Server-Cert cert-{}'],
                                          ['subsystem', 'subsystemCert cert-{}'],
                                          ['audit_signing', 'auditSigningCert cert-{} OCSP']))
def test_pki_server_subsystem_cert_validate_ocsp_clone_certs(ansible_module, cert_id, nick):
    """
    :id: bd9eda31-ce6d-4d3c-a778-bf89b612c630
    :Title: Test pki-server subsystem-cert-validate OCSP Clone Signing certificate
    :Description: test pki-server subsystem-cert-validate command
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Steps:
    :ExpectedResults: 
        1. Verify whether pki-server subsystem-cert-validate command validates the clone OCSP
        signing certificate.
    """
    cert_out = ansible_module.command('pki-server subsystem-cert-validate'
                                      ' -i {} ocsp {}'.format(constants.CLONEOCSP1_INSTANCE_NAME,
                                                              cert_id))
    for result in cert_out.values():
        if result['rc'] == 0:
            assert "Cert ID: {}".format(cert_id) in result['stdout']
            assert "Nickname: {}".format(nick.format(constants.CLONEOCSP1_INSTANCE_NAME)) in \
                   result['stdout']
            assert "Usage:" in result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            assert "Status: VALID" in result['stdout']
            log.info("Validate certificate : {}".format(cert_id))
            log.info("Validate certificate Nick : {}".format(nick.format(constants.CLONEOCSP1_INSTANCE_NAME)))
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run {}.".format(" ".join(result['cmd'])))
            pytest.skip()


@pytest.mark.skipif("TOPOLOGY <= 3")
@pytest.mark.parametrize('cert_id,nick', (['sslserver', 'Server-Cert cert-{}'],
                                          ['subsystem', 'subsystemCert cert-{}'],
                                          ['audit_signing', 'auditSigningCert cert-{} TKS']))
def test_pki_server_subsystem_cert_validate_tks_clone_certs(ansible_module, cert_id, nick):
    """
    :id: 01dc0c2d-b962-4793-8a76-00c2e55bade0
    :Title: Test pki-server subsystem-cert-validate TKS Clone Subsystem certificate
    :Description: test pki-server subsystem-cert-validate command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults: 
        1. Verify whether pki-server subsystem-cert-validate command validates the clone tks 
        subsystem certificate.
    """
    cert_out = ansible_module.command('pki-server subsystem-cert-validate'
                                      ' -i {} tks {}'.format(constants.CLONETKS1_INSTANCE_NAME,
                                                             cert_id))
    for result in cert_out.values():
        if result['rc'] == 0:
            assert "Cert ID: {}".format(cert_id) in result['stdout']
            assert "Nickname: {}".format(nick.format(constants.CLONETKS1_INSTANCE_NAME)) in \
                   result['stdout']
            assert "Usage:" in result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            assert "Status: VALID" in result['stdout']
            log.info("Validate certificate : {}".format(cert_id))
            log.info("Validate certificate Nick : {}".format(nick.format(constants.CLONETKS1_INSTANCE_NAME)))
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run {}.".format(" ".join(result['cmd'])))
            pytest.skip()


@pytest.mark.skipif("TOPOLOGY <= 3")
@pytest.mark.parametrize('cert_id,nick', (['signing', 'caSigningCert cert-{} CA'],
                                          ['ocsp_signing', 'ocspSigningCert cert-{} CA'],
                                          ['sslserver', 'Server-Cert cert-{}'],
                                          ['subsystem', 'subsystemCert cert-{}'],
                                          ['audit_signing', 'auditSigningCert cert-{} CA']))
def test_pki_server_subsystem_cert_validate_subca_certs(ansible_module, cert_id, nick):
    """
    :id: 92dd4213-d2d7-4aec-b85f-1e397270ca20
    :Title: Test pki-server subsystem-cert-validate Sub CA Signing certificate
    :Description: test pki-server subsystem-cert-validate command
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement: Pki Server Subsystem 
    :CaseComponent: \-
    :Steps:
    :ExpectedResults: 
        1. Verify whether pki-server subsystem-cert-validate command validates the subca signing 
        certificate.
    """
    cert_out = ansible_module.command('pki-server subsystem-cert-validate'
                                      ' -i {} ca {}'.format(constants.SUBCA1_INSTANCE_NAME,
                                                            cert_id))
    for result in cert_out.values():
        if result['rc'] == 0:
            assert "Cert ID: {}".format(cert_id) in result['stdout']
            assert "Nickname: {}".format(nick.format(constants.SUBCA1_INSTANCE_NAME)) in \
                   result['stdout']
            assert "Usage:" in result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            assert "Status: VALID" in result['stdout']
            log.info("Validate certificate : {}".format(cert_id))
            log.info("Validate certificate Nick : {}".format(nick.format(constants.SUBCA1_INSTANCE_NAME)))
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run {}.".format(" ".join(result['cmd'])))
            pytest.skip()


def test_pki_server_subsystem_cert_validate_junk_instance(ansible_module):
    """
    :id: 8c844041-0ba6-4651-a562-209a85eff2cb
    :Title: Test pki-server subsystem-cert-validate junk instance name.
    :Description: test pki-server subsystem-cert-validate command
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :ExpectedResults: 
        1. Verify whether pki-server subsystem-cert-validate command throws error when junk 
        Instance name is supplied.
    """
    junk_instance = ''.join(random.choice(string.ascii_uppercase + string.digits)
                            for _ in range(10))
    cert_out = ansible_module.command('pki-server subsystem-cert-validate'
                                      ' -i {} ca signing'.format(junk_instance))
    for result in cert_out.values():
        if result['rc'] == 0:
            assert "Usage:" in result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            assert "Status: VALID" in result['stdout']
            log.error("Failed to run {}.".format(" ".join(result['cmd'])))
            pytest.skip()
        else:
            assert "ERROR: Invalid instance {}".format(junk_instance) in result['stderr']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))


def test_pki_server_subsystem_cert_validate_junk_subsystemType(ansible_module):
    """
    :id: 90e232ef-7515-4e99-b7fc-9d7ab4cb7454
    :Title: Test pki-server subsystem-cert-validate Junk subsystem type
    :Description: test pki-server subsystem-cert-validate command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults: 
        1. Verify whether pki-server subsystem-cert-validate command throws error when junk 
        subsystem type is supplied.
    """
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
        security_domain = constants.CA_SECURITY_DOMAIN_NAME
    else:
        instance = constants.CA_INSTANCE_NAME
        security_domain = constants.CA_SECURITY_DOMAIN_NAME
    junk_instance = ''.join(random.choice(string.ascii_uppercase + string.digits)
                            for _ in range(10))
    cert_out = ansible_module.command('pki-server subsystem-cert-validate'
                                      ' -i {} {} signing'.format(instance, junk_instance))
    for result in cert_out.values():
        if result['rc'] == 0:
            assert "Usage:" in result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            assert "Status: VALID" in result['stdout']
            log.error("Failed to run {}.".format(" ".join(result['cmd'])))
            pytest.skip()
        else:
            assert "ERROR: No {} subsystem in instance {}.".format(junk_instance, instance) in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))


@pytest.mark.skipif("TOPOLOGY <= 3")
def test_pki_server_subsystem_cert_validate_junk_certID(ansible_module):
    """
    :id: 8f365f88-3e33-43c4-b477-feea74acd28d
    :Title: Test pki-server subsystem-cert-validate with junk cert-id
    :Description: test pki-server subsystem-cert-validate command
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement: Pki Server Subsystem
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server subsystem-cert-validate command throws error when
        junk cert ID is supplied.
    """
    junk_certID = ''.join(random.choice(string.ascii_uppercase + string.digits)
                          for _ in range(10))
    cert_validate_output = ansible_module.command('pki-server subsystem-cert-validate -i {} '
                                                  'ca {}'.format(constants.CA_INSTANCE_NAME,
                                                                 junk_certID))
    for result in cert_validate_output.values():
        if result['rc'] == 0:
            assert "Validation failed" in result['stdout']

        else:
            log.error("Failed to run {}.".format(" ".join(result['cmd'])))
            pytest.skip()


@pytest.mark.skipif("TOPOLOGY <= 3")
def test_pki_server_subsystem_cert_validate_disabled_subsystem(ansible_module):
    """
    :id: c667bbbd-b9dd-4c20-bdfd-a81fa2117e44
    :Title: Test pki-server subsystem-cert-validate disabled subsystem certificate
    :Description: test pki-server subsystem-cert-validate command
    :Requirement: Pki Server Subsystem
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server subsystem-cert-validate command validates the cert
        when subsystem is disabled.
    """
    ansible_module.command('pki-server  subsystem-disable '
                           '-i {} ca'.format(constants.CA_INSTANCE_NAME))
    cert_validate_output = ansible_module.command('pki-server subsystem-cert-validate '
                                                  '-i {} ca audit_signing'.format(
        constants.CA_INSTANCE_NAME))
    for result in cert_validate_output.values():
        if result['rc'] == 0:
            assert "Cert ID: audit_signing" in result['stdout']
            assert "Nickname: auditSigningCert cert-" + constants.CA_INSTANCE_NAME + " CA" in \
                   result['stdout']
            assert "Usage: ObjectSigner" in result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            assert "Status: VALID" in result['stdout']
            assert "Validation succeeded" in result['stdout']
            log.info("Validate certificate : {}".format('audit_signing'))
            log.info("Validate certificate Nick : auditSigningCert cert-" + constants.CA_INSTANCE_NAME + " CA")
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run {}.".format(" ".join(result['cmd'])))
            pytest.skip()
    ansible_module.command('pki-server subsystem-enable -i {} '
                           'ca'.format(constants.CA_INSTANCE_NAME))
