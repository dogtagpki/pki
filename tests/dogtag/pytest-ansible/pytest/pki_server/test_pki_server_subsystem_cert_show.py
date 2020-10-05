"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki-server subsystem cli commands needs to be tested:
#   pki-server subsystem-cert-show
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

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

TOPOLOGY = int(''.join(constants.CA_INSTANCE_NAME.split("-")[1]))
log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)


# @pytest.mark.xfail(reason='BZ-1340718')
def test_pki_server_subsystem_cert_show_help(ansible_module):
    """
    :id: 7c87ea5e-aee8-49d5-856e-a707cd3ca0eb
    :Title: Test pki-server subsystem-cert-show --help command
    :Description: test pki-server subsystem-cert-show command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server subsystem-cert-show --help command shows the help option.
    """
    help_out = ansible_module.command('pki-server subsystem-cert-show --help')
    for result in help_out.values():
        if result['rc'] == 0:

            assert "Usage: pki-server subsystem-cert-show [OPTIONS] " \
                   "<subsystem ID> <cert ID>" in result['stdout']
            assert "-i, --instance <instance ID>    Instance ID " \
                   "(default: pki-tomcat)." in result['stdout']
            assert "--show-all                  Show all attributes." in result['stdout']
            assert "-v, --verbose                   Run in verbose mode." in result['stdout']
            assert "--help                      Show help message." in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.info("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()


@pytest.mark.parametrize('cert_id,nick', (['signing', 'caSigningCert cert-{} CA'],
                                          ['ocsp_signing', 'ocspSigningCert cert-{} CA'],
                                          ['sslserver', 'Server-Cert cert-{}'],
                                          ['subsystem', 'subsystemCert cert-{}'],
                                          ['audit_signing', 'auditSigningCert cert-{} CA']))
def test_pki_server_subsystem_cert_show_ca_signing(ansible_module, cert_id, nick):
    """
    :id: 96c570e8-bd95-4b2b-9064-b02afcce0428
    :Title: Test pki-server subsystem-cert-show ca signing certificate command.
    :Description: Test pki-server subsystem-cert-show  ca singing certificate command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. run pki-server subsystem-cert-show ca signing
        2. run pki-server subsystem-cert-show ca ocsp_signing
        3. run pki-server subsystem-cert-show ca sslserver
        4. run pki-server subsystem-cert-show ca subsystem
        5. run pki-server subsystem-cert-show ca audit_signing
    :ExpectedResults:
        1. pki-server subsystem-cert-show should show the ca signing certificate info.
        2. pki-server subsystem-cert-show should show the ocsp_signing certificate info.
        3. pki-server subsystem-cert-show should show the sslserver certificate info.
        4. pki-server subsystem-cert-show should show the subsystem certificate info.
        5. pki-server subsystem-cert-show should show the audit_signing certificate info.
    """
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
    else:
        instance = constants.CA_INSTANCE_NAME
    signing_out = ansible_module.command('pki-server subsystem-cert-show '
                                         '-i {} ca {}'.format(instance, cert_id))
    for result in signing_out.values():
        if result['rc'] == 0:
            assert "Cert ID: {}".format(cert_id) in result['stdout']
            assert "Nickname: {}".format(nick.format(instance)) in result['stdout']
            assert "Token: internal" in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.info("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()


@pytest.mark.parametrize('cert_id,nick', (['transport', 'transportCert cert-{} KRA'],
                                          ['storage', 'storageCert cert-{} KRA'],
                                          ['sslserver', 'Server-Cert cert-{}'],
                                          ['subsystem', 'subsystemCert cert-{}'],
                                          ['audit_signing', 'auditSigningCert cert-{} KRA']))
def test_pki_server_subsystem_cert_show_kra_certs(ansible_module, cert_id, nick):
    """
    :id: 4d096f8b-da7e-4b54-9e6a-2d67142b3ed6
    :Title: Test pki-server subsystem cert show kra transport certificate
    :Description: test pki-server subsystem-cert-show show kra transport certificate command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki-server subsystem-cert-show kra transport
        2. pki-server subsystem-cert-show kra storage
        3. pki-server subsystem-cert-show kra sslserver
        4. pki-server subsystem-cert-show kra subsystem
        5. pki-server subsystem-cert-show kra audit_signing
    :ExpectedResults:
        1. pki-server subsystem-cert-show should show the kra transport certificate info.
        2. pki-server subsystem-cert-show should show the kra storage certificate info.
        3. pki-server subsystem-cert-show should show the kra sslserver certificate info.
        4. pki-server subsystem-cert-show should show the kra subsystem certificate info.
        5. pki-server subsystem-cert-show should show the kra audit_signing certificate info.
    """
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
    else:
        instance = constants.KRA_INSTANCE_NAME
    signing_out = ansible_module.command('pki-server subsystem-cert-show '
                                         '-i {} kra {}'.format(instance, cert_id))
    for result in signing_out.values():
        if result['rc'] == 0:
            assert "Cert ID: {}".format(cert_id) in result['stdout']
            assert "Nickname: {}".format(nick.format(instance)) in result['stdout']
            assert "Token:" in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.info("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()



@pytest.mark.parametrize('cert_id,nick', (['signing', 'ocspSigningCert cert-{} OCSP'],
                                          ['sslserver', 'Server-Cert cert-{}'],
                                          ['subsystem', 'subsystemCert cert-{}'],
                                          ['audit_signing', 'auditSigningCert cert-{} OCSP']))
def test_pki_server_subsystem_cert_show_ocsp_certs(ansible_module, cert_id, nick):
    """
    :id: a3b94b99-254e-409a-b3ab-8d5276ad509a
    :Title: Test pki-server subsystemc-cert-show ocsp certificates
    :Description: test pki-server subsystem-cert-show command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki-server subsystem-cert-show ocsp transport
        2. pki-server subsystem-cert-show ocsp sslserver
        3. pki-server subsystem-cert-show ocsp subsystem
        4. pki-server subsystem-cert-show ocsp audit_signing
    :ExpectedResults:
        1. pki-server subsystem-cert-show should show the ocsp transport certificate info.
        2. pki-server subsystem-cert-show should show the ocsp sslserver certificate info.
        3. pki-server subsystem-cert-show should show the ocsp subsystem certificate info.
        4. pki-server subsystem-cert-show should show the ocsp audit_signing certificate info.
    """
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
    else:
        instance = constants.OCSP_INSTANCE_NAME
    signing_out = ansible_module.command('pki-server subsystem-cert-show '
                                         '-i {} ocsp {}'.format(instance, cert_id))
    for result in signing_out.values():
        if result['rc'] == 0:
            assert "Cert ID: {}".format(cert_id) in result['stdout']
            assert "Nickname: {}".format(nick.format(instance)) in result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.info("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()


@pytest.mark.parametrize('cert_id,nick', (['sslserver', 'Server-Cert cert-{}'],
                                          ['subsystem', 'subsystemCert cert-{}'],
                                          ['audit_signing', 'auditSigningCert cert-{} TKS']))
def test_pki_server_subsystem_cert_show_tks_sslserver(ansible_module, cert_id, nick):
    """
    :id: b5f676e9-72cb-4313-bada-5444f694fc1c
    :Title: Test pki-server subsystem-cert-show TKS SSL Server certificate
    :Description: test pki-server subsystem-cert-show command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki-server subsystem-cert-show tks sslserver
        2. pki-server subsystem-cert-show tks subsystem
        3. pki-server subsystem-cert-show tks audit_signing
    :ExpectedResults:
        1. pki-server subsystem-cert-show should show the tks sslserver certificate info.
        2. pki-server subsystem-cert-show should show the tks subsystem certificate info.
        3. pki-server subsystem-cert-show should show the tks audit_signing certificate info.
    """
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
    else:
        instance = constants.TKS_INSTANCE_NAME
    signing_out = ansible_module.command('pki-server subsystem-cert-show '
                                         '-i {} tks {}'.format(instance, cert_id))
    for result in signing_out.values():
        if result['rc'] == 0:
            assert "Cert ID: {}".format(cert_id) in result['stdout']
            assert "Nickname: {}".format(nick.format(instance)) in result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.info("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()


@pytest.mark.parametrize('cert_id,nick', (['sslserver', 'Server-Cert cert-{}'],
                                          ['subsystem', 'subsystemCert cert-{}'],
                                          ['audit_signing', 'auditSigningCert cert-{} TPS']))
def test_pki_server_subsystem_cert_show_tps_sslserver(ansible_module, cert_id, nick):
    """
    :id: db63f6c2-20ac-43a9-afdd-2cb9a8a1bcd1
    :Title: Test pki-server subsystem-cert-show TPS SSL Server Certificate
    :Description: test pki-server subsystem-cert-show command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki-server subsystem-cert-show tps sslserver
        2. pki-server subsystem-cert-show tps subsystem
        3. pki-server subsystem-cert-show tps audit_signing
    :ExpectedResults:
        1. pki-server subsystem-cert-show should show the tps sslserver certificate info.
        2. pki-server subsystem-cert-show should show the tps subsystem certificate info.
        3. pki-server subsystem-cert-show should show the tps audit_signing certificate info.

    """
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
    else:
        instance = constants.TPS_INSTANCE_NAME
    signing_out = ansible_module.command('pki-server subsystem-cert-show '
                                         '-i {} tps {}'.format(instance, cert_id))
    for result in signing_out.values():
        if result['rc'] == 0:
            assert "Cert ID: {}".format(cert_id) in result['stdout']
            assert "Nickname: {}".format(nick.format(instance)) in result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.info("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()


@pytest.mark.skipif("TOPOLOGY <= 3")
@pytest.mark.parametrize('cert_id,nick', (['signing', 'caSigningCert cert-{} CA'],
                                          ['ocsp_signing', 'ocspSigningCert cert-{} CA'],
                                          ['sslserver', 'Server-Cert cert-{}'],
                                          ['subsystem', 'subsystemCert cert-{}'],
                                          ['audit_signing', 'auditSigningCert cert-{} CA']))
def test_pki_server_subsystem_cert_show_clone_ca_certs(ansible_module, cert_id, nick):
    """
    :id: c5d8273f-1b41-439f-92ee-f5603df83d8a
    :Title: Test pki-server subsystem-cert-show Clone CA Signing Certificate
    :Description: test pki-server subsystem-cert-show command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. run pki-server subsystem-cert-show ca signing
        2. run pki-server subsystem-cert-show ca ocsp_signing
        3. run pki-server subsystem-cert-show ca sslserver
        4. run pki-server subsystem-cert-show ca subsystem
        5. run pki-server subsystem-cert-show ca audit_signing
    :ExpectedResults:
        1. pki-server subsystem-cert-show should show the ca signing certificate info.
        2. pki-server subsystem-cert-show should show the ocsp_signing certificate info.
        3. pki-server subsystem-cert-show should show the sslserver certificate info.
        4. pki-server subsystem-cert-show should show the subsystem certificate info.
        5. pki-server subsystem-cert-show should show the audit_signing certificate info.
    """
    signing_out = ansible_module.command('pki-server subsystem-cert-show '
                                         '-i {} ca {}'.format(constants.CLONECA1_INSTANCE_NAME,
                                                              cert_id))
    for result in signing_out.values():
        if result['rc'] == 0:
            assert "Cert ID: {}".format(cert_id) in result['stdout']
            assert "Nickname: {}".format(nick.format(constants.CLONECA1_INSTANCE_NAME)) in \
                   result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.info("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()


@pytest.mark.skipif("TOPOLOGY <= 3")
@pytest.mark.parametrize('cert_id,nick', (['transport', 'transportCert cert-{} KRA'],
                                          ['storage', 'storageCert cert-{} KRA'],
                                          ['sslserver', 'Server-Cert cert-{}'],
                                          ['subsystem', 'subsystemCert cert-{}'],
                                          ['audit_signing', 'auditSigningCert cert-{} KRA']))
def test_pki_server_subsystem_cert_show_clone_kra_certs(ansible_module, cert_id, nick):
    """
    :id: \9f9bb78d-1596-4cd7-89ef-621e426bb025
    :Title: Test pki-server subsystem-cert-show Clone KRA Transport Certificate
    :Description: test pki-server subsystem-cert-show command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki-server subsystem-cert-show kra transport
        2. pki-server subsystem-cert-show kra storage
        3. pki-server subsystem-cert-show kra sslserver
        4. pki-server subsystem-cert-show kra subsystem
        5. pki-server subsystem-cert-show kra audit_signing
    :ExpectedResults:
        1. pki-server subsystem-cert-show should show the kra transport certificate info.
        2. pki-server subsystem-cert-show should show the kra storage certificate info.
        3. pki-server subsystem-cert-show should show the kra sslserver certificate info.
        4. pki-server subsystem-cert-show should show the kra subsystem certificate info.
        5. pki-server subsystem-cert-show should show the kra audit_signing certificate info.
    """
    signing_out = ansible_module.command('pki-server subsystem-cert-show '
                                         '-i {} kra {}'.format(constants.CLONEKRA1_INSTANCE_NAME,
                                                               cert_id))
    for result in signing_out.values():
        if result['rc'] == 0:
            assert "Cert ID: {}".format(cert_id) in result['stdout']
            assert "Nickname: {}".format(nick.format(constants.CLONEKRA1_INSTANCE_NAME)) in \
                   result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.info("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()


@pytest.mark.skipif("TOPOLOGY <= 3")
@pytest.mark.parametrize('cert_id,nick', (['signing', 'ocspSigningCert cert-{} OCSP'],
                                          ['sslserver', 'Server-Cert cert-{}'],
                                          ['subsystem', 'subsystemCert cert-{}'],
                                          ['audit_signing', 'auditSigningCert cert-{} OCSP']))
def test_pki_server_subsystem_cert_show_clone_ocsp_certs(ansible_module, cert_id, nick):
    """
    :id: 13354952-e637-4596-b9d7-c9f8530f02fd
    :Title: Test pki-server subsystem-cert-show Clone OCSP Signing Certificate
    :Description: test pki-server subsystem-cert-show command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki-server subsystem-cert-show ocsp transport
        2. pki-server subsystem-cert-show ocsp sslserver
        3. pki-server subsystem-cert-show ocsp subsystem
        4. pki-server subsystem-cert-show ocsp audit_signing
    :ExpectedResults:
        1. pki-server subsystem-cert-show should show the ocsp transport certificate info.
        2. pki-server subsystem-cert-show should show the ocsp sslserver certificate info.
        3. pki-server subsystem-cert-show should show the ocsp subsystem certificate info.
        4. pki-server subsystem-cert-show should show the ocsp audit_signing certificate info.
    """
    signing_out = ansible_module.command('pki-server subsystem-cert-show '
                                         '-i {} ocsp {}'.format(constants.CLONEOCSP1_INSTANCE_NAME,
                                                                cert_id))
    for result in signing_out.values():
        if result['rc'] == 0:
            assert "Cert ID: {}".format(cert_id) in result['stdout']
            assert "Nickname: {}".format(nick.format(constants.CLONEOCSP1_INSTANCE_NAME)) in \
                   result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.info("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()


@pytest.mark.skipif("TOPOLOGY <= 3")
@pytest.mark.parametrize('cert_id,nick', (['sslserver', 'Server-Cert cert-{}'],
                                          ['subsystem', 'subsystemCert cert-{}'],
                                          ['audit_signing', 'auditSigningCert cert-{} TKS']))
def test_pki_server_subsystem_cert_show_clone_tks_certs(ansible_module, cert_id, nick):
    """
    :id: ae75df62-3a5a-45e0-ae09-835ccd8e6cea
    :Title: Test pki-server subsystem-cert-show TKS SSL Server Certificate
    :Description: test pki-server subsystem-cert-show command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki-server subsystem-cert-show tks sslserver
        2. pki-server subsystem-cert-show tks subsystem
        3. pki-server subsystem-cert-show tks audit_signing
    :ExpectedResults:
        1. pki-server subsystem-cert-show should show the tks sslserver certificate info.
        2. pki-server subsystem-cert-show should show the tks subsystem certificate info.
        3. pki-server subsystem-cert-show should show the tks audit_signing certificate info.

    """
    signing_out = ansible_module.command('pki-server subsystem-cert-show '
                                         '-i {} tks {}'.format(constants.CLONETKS1_INSTANCE_NAME,
                                                               cert_id))
    for result in signing_out.values():
        if result['rc'] == 0:
            assert "Cert ID: {}".format(cert_id) in result['stdout']
            assert "Nickname: {}".format(nick.format(constants.CLONETKS1_INSTANCE_NAMENE)) in \
                   result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.info("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()


@pytest.mark.skipif("TOPOLOGY <= 3")
@pytest.mark.parametrize('cert_id,nick', (['signing', 'caSigningCert cert-{} CA'],
                                          ['ocsp_signing', 'ocspSigningCert cert-{} CA'],
                                          ['sslserver', 'Server-Cert cert-{}'],
                                          ['subsystem', 'subsystemCert cert-{}'],
                                          ['audit_signing', 'auditSigningCert cert-{} CA']))
def test_pki_server_subsystem_cert_show_subca_signing(ansible_module, cert_id, nick):
    """
    :id: ae75df62-3a5a-45e0-ae09-835ccd8e6cea
    :Title: Test pki-server subsystem-cert-show Sub CA Signing Certificate
    :Description: test pki-server subsystem-cert-show command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. run pki-server subsystem-cert-show ca signing
        2. run pki-server subsystem-cert-show ca ocsp_signing
        3. run pki-server subsystem-cert-show ca sslserver
        4. run pki-server subsystem-cert-show ca subsystem
        5. run pki-server subsystem-cert-show ca audit_signing
    :ExpectedResults:
        1. pki-server subsystem-cert-show should show the ca signing certificate info.
        2. pki-server subsystem-cert-show should show the ocsp_signing certificate info.
        3. pki-server subsystem-cert-show should show the sslserver certificate info.
        4. pki-server subsystem-cert-show should show the subsystem certificate info.
        5. pki-server subsystem-cert-show should show the audit_signing certificate info.

    """
    signing_out = ansible_module.command('pki-server subsystem-cert-show '
                                         '-i {} ca {}'.format(constants.CLONECA1_INSTANCE_NAME,
                                                              cert_id))
    for result in signing_out.values():
        if result['rc'] == 0:
            assert "Cert ID: {}".format(cert_id) in result['stdout']
            assert "Nickname: {}".format(nick.format(constants.CLONECA1_INSTANCE_NAME)) in \
                   result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.info("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()
