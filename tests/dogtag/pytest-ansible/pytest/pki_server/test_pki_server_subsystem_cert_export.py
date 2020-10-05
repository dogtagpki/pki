"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki-server subsystem cli commands needs to be tested:
#   pki-server subsystem-cert-export
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


def test_pki_server_subsystem_cert_export_help(ansible_module):
    """
    :id: e61d2329-a42d-40a1-8beb-acf8722ea804
    :Title: Test pki-server subsystem-cert-export --help command, BZ: 1340718
    :Description: test pki-server subsystem-cert-export --help command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server subsystem-cert-export command exports --help shows help
        options.
    """
    help_out = ansible_module.command('pki-server subsystem-cert-export --help')
    for result in help_out.values():
        if result['rc'] == 0:

            assert "-i, --instance <instance ID>       Instance ID (default: pki-tomcat)" in \
                   result['stdout']
            assert "--cert-file <path>             Output file to store the exported certificate " \
                   "in PEM format" in result['stdout']
            assert "--csr-file <path>              Output file to store the exported CSR " \
                   "in PEM format" in result['stdout']
            assert "--pkcs12-file <path>           Output file to store the exported certificate " \
                   "and key in PKCS #12 format" in result['stdout']
            assert "--pkcs12-password <password>   Password for the PKCS #12 file" in \
                   result['stdout']
            assert "--pkcs12-password-file <path>  Input file containing the password for " \
                   "the PKCS #12 file" in result['stdout']
            assert "--append                       Append into an existing PKCS #12 file" in \
                   result['stdout']
            assert "--no-trust-flags               Do not include trust flags" in \
                   result['stdout']
            assert "--no-key                       Do not include private key" in \
                   result['stdout']
            assert "--no-chain                     Do not include certificate chain" in \
                   result['stdout']
            assert "-v, --verbose                      Run in verbose mode" in result['stdout']
            assert "--debug                        Run in debug mode" in result['stdout']
            assert "--help                         Show help message" in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()


@pytest.mark.parametrize('cert_id', ('signing', 'ocsp_signing', 'sslserver',
                                     'subsystem', 'audit_signing'))
def test_pki_server_subsystem_cert_export_ca_certs(ansible_module, cert_id):
    """
    :id: 34a8fe13-4654-479b-a775-3898c2ba4d69
    :Title: Test pki-server subsystem-cert-export CA Signing certificate export
    :Description: Test pki-server subsystem-cert-export command, will export signing, ocsp_signing,
                  SSLServer, Subsystem and Audit Signing certificate
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether signing certificate got exported in .pem .req and .p12 file.
        2. Verify whether ocsp_signing certificate got exported in .pem .req and .p12 file.
        3. Verify whether sslserver certificate got exported in .pem .req and .p12 file.
        4. Verify whether subsystem certificate got exported in .pem .req and .p12 file.
        5. Verify whether audit_signing certificate got exported in .pem .req and .p12 file.
    """
    cert_file = '/tmp/ca_{}.pem'.format(cert_id)
    csr_file = '/tmp/ca_{}_csr.pem'.format(cert_id)
    p12_file = '/tmp/ca_{}.p12'.format(cert_id)
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
    else:
        instance = constants.CA_INSTANCE_NAME
    cert_export = 'pki-server subsystem-cert-export -i {} --cert-file {} --csr-file {} ' \
                  '--pkcs12-file {} --pkcs12-password {} ' \
                  'ca {}'.format(instance, cert_file, csr_file, p12_file,
                                 constants.CLIENT_PKCS12_PASSWORD, cert_id)
    signing_out = ansible_module.command(cert_export)
    for result in signing_out.values():
        if result['rc'] == 0:
            assert "Export complete" in result['stdout']
            for f in [cert_file, csr_file, p12_file]:
                exists = ansible_module.stat(path=f)
                for res in exists.values():
                    assert res['stat']['exists']
                    log.info("File {} exists.".format(f))
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()
    for f in [cert_file, csr_file, p12_file]:
        ansible_module.command('rm -rf {}'.format(f))


@pytest.mark.parametrize('cert_id', ('transport', 'storage', 'sslserver', 'subsystem',
                                     'audit_signing'))
def test_pki_server_subsystem_cert_export_kra_certs(ansible_module, cert_id):
    """
    :id: 723c88c4-126e-4581-8726-406190f1dc85
    :Title: Test pki-server subsystem-cert-export KRA certificates
    :Description: Test pki-server subsystem-cert-export command, will export transport, storage,
                  SSLServer, Subsystem and Audit Signing certificate
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether transport certificate got exported in .pem .req and .p12 file.
        2. Verify whether storage certificate got exported in .pem .req and .p12 file.
        3. Verify whether sslserver certificate got exported in .pem .req and .p12 file.
        4. Verify whether subsystem certificate got exported in .pem .req and .p12 file.
        5. Verify whether audit_signing certificate got exported in .pem .req and .p12 file.
    """
    cert_file = '/tmp/kra_{}.pem'.format(cert_id)
    csr_file = '/tmp/kra_{}_csr.pem'.format(cert_id)
    p12_file = '/tmp/kra_{}.p12'.format(cert_id)
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
    else:
        instance = constants.KRA_INSTANCE_NAME
    cert_export = 'pki-server subsystem-cert-export -i {} --cert-file {} --csr-file {} ' \
                  '--pkcs12-file {} --pkcs12-password {} ' \
                  'kra {}'.format(instance, cert_file, csr_file, p12_file,
                                  constants.CLIENT_PKCS12_PASSWORD, cert_id)

    signing_out = ansible_module.command(cert_export)
    for result in signing_out.values():
        if result['rc'] == 0:
            assert "Export complete" in result['stdout']
            for f in [cert_file, csr_file, p12_file]:
                exists = ansible_module.stat(path=f)
                for res in exists.values():
                    assert res['stat']['exists']
                    log.info("File {} exists.".format(f))
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()
    for f in [cert_file, csr_file, p12_file]:
        ansible_module.command('rm -rf {}'.format(f))


@pytest.mark.parametrize('cert_id', ('signing', 'sslserver', 'subsystem', 'audit_signing'))
def test_pki_server_subsystem_cert_export_ocsp_certs(ansible_module, cert_id):
    """
    :id: 80778f63-1139-42c1-92b3-59c74005605a
    :Title: Test pki-server subsystem-cert-export OCSP certificates export
    :Description: Test pki-server subsystem-cert-export command, will export signing,
                  SSLServer, Subsystem and Audit Signing certificate
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether signing certificate got exported in .pem .req and .p12 file.
        2. Verify whether sslserver certificate got exported in .pem .req and .p12 file.
        3. Verify whether subsystem certificate got exported in .pem .req and .p12 file.
        4. Verify whether audit_signing certificate got exported in .pem .req and .p12 file.
    """
    cert_file = '/tmp/ocsp_{}.pem'.format(cert_id)
    csr_file = '/tmp/ocsp_{}_csr.pem'.format(cert_id)
    p12_file = '/tmp/ocsp_{}.p12'.format(cert_id)
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
    else:
        instance = constants.OCSP_INSTANCE_NAME
    cert_export = 'pki-server subsystem-cert-export -i {} --cert-file {} --csr-file {} ' \
                  '--pkcs12-file {} --pkcs12-password {} ' \
                  'ocsp {}'.format(instance, cert_file, csr_file, p12_file,
                                   constants.CLIENT_PKCS12_PASSWORD, cert_id)
    signing_out = ansible_module.command(cert_export)
    for result in signing_out.values():
        if result['rc'] == 0:
            assert "Export complete" in result['stdout']
            for f in [cert_file, csr_file, p12_file]:
                exists = ansible_module.stat(path=f)
                for res in exists.values():
                    assert res['stat']['exists']
                    log.info("File {} exists.".format(f))
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()
    for f in [cert_file, csr_file, p12_file]:
        ansible_module.command('rm -rf {}'.format(f))


@pytest.mark.parametrize('cert_id', ('sslserver', 'subsystem', 'audit_signing'))
def test_pki_server_subsystem_cert_export_tks_subsystem(ansible_module, cert_id):
    """
    :id: 8709e5ee-d9c5-4cb4-972a-b0458548fd62
    :Title: Test pki-server subsystem-cert-export TKS Subsystem certificate export
    :Description: Test pki-server subsystem-cert-export command, will export signing,
                  SSLServer, Subsystem and Audit Signing certificate
    :Requirement: Pki Server Subsystem
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether signing certificate got exported in .pem .req and .p12 file.
        2. Verify whether sslserver certificate got exported in .pem .req and .p12 file.
        3. Verify whether subsystem certificate got exported in .pem .req and .p12 file.
        4. Verify whether audit_signing certificate got exported in .pem .req and .p12 file.
    """
    cert_file = '/tmp/tks_{}.pem'.format(cert_id)
    csr_file = '/tmp/tks_{}_csr.pem'.format(cert_id)
    p12_file = '/tmp/tks_{}.p12'.format(cert_id)
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
    else:
        instance = constants.TKS_INSTANCE_NAME
    cert_export = 'pki-server subsystem-cert-export -i {} --cert-file {} --csr-file {} ' \
                  '--pkcs12-file {} --pkcs12-password {} ' \
                  'tks {}'.format(instance, cert_file, csr_file, p12_file,
                                  constants.CLIENT_PKCS12_PASSWORD, cert_id)
    signing_out = ansible_module.command(cert_export)
    for result in signing_out.values():
        if result['rc'] == 0:
            assert "Export complete" in result['stdout']
            for f in [cert_file, csr_file, p12_file]:
                exists = ansible_module.stat(path=f)
                for res in exists.values():
                    assert res['stat']['exists']
                    log.info("File {} exists.".format(f))
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()
    for f in [cert_file, csr_file, p12_file]:
        ansible_module.command('rm -rf {}'.format(f))


@pytest.mark.parametrize('cert_id', ('sslserver', 'subsystem', 'audit_signing'))
def test_pki_server_subsystem_cert_export_tps_subsystem(ansible_module, cert_id):
    """
    :id: fff185ff-f5d9-47ae-8bcb-02c19c54aa73
    :Title: Test pki-server subsystem-cert-export TPS Subsystem certificate export
    :Description: Test pki-server subsystem-cert-export command, will export signing,
                  SSLServer, Subsystem and Audit Signing certificate
    :Requirement: Pki Server Subsystem
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether signing certificate got exported in .pem .req and .p12 file.
        2. Verify whether sslserver certificate got exported in .pem .req and .p12 file.
        3. Verify whether subsystem certificate got exported in .pem .req and .p12 file.
        4. Verify whether audit_signing certificate got exported in .pem .req and .p12 file.
    """
    cert_file = '/tmp/tps_{}.pem'.format(cert_id)
    csr_file = '/tmp/tps_{}_csr.pem'.format(cert_id)
    p12_file = '/tmp/tps_{}.p12'.format(cert_id)
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
    else:
        instance = constants.TPS_INSTANCE_NAME
    cert_export = 'pki-server subsystem-cert-export -i {} --cert-file {} --csr-file {} ' \
                  '--pkcs12-file {} --pkcs12-password {} ' \
                  'tps {}'.format(instance, cert_file, csr_file, p12_file,
                                  constants.CLIENT_PKCS12_PASSWORD, cert_id)
    signing_out = ansible_module.command(cert_export)
    for result in signing_out.values():
        if result['rc'] == 0:
            assert "Export complete" in result['stdout']
            for f in [cert_file, csr_file, p12_file]:
                exists = ansible_module.stat(path=f)
                for res in exists.values():
                    assert res['stat']['exists']
                    log.info("File {} exists.".format(f))
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()
    for f in [cert_file, csr_file, p12_file]:
        ansible_module.command('rm -rf {}'.format(f))


@pytest.mark.skipif("TOPOLOGY <= 3")
@pytest.mark.parametrize('cert_id', ('signing', 'ocsp_signing', 'sslserver',
                                     'subsystem', 'audit_signing'))
def test_pki_server_subsystem_cert_export_clone_ca_certs(ansible_module, cert_id):
    """
    :id: 32607193-db74-49d9-aff9-2e18c2f6cd61
    :Title: Test pki-server subsystem-cert-export Clone CA Signing certificate export
    :Description: Test pki-server subsystem-cert-export command, will export signing,
                  SSLServer, Subsystem and Audit Signing certificate
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether signing certificate got exported in .pem .req and .p12 file.
        2. Verify whether sslserver certificate got exported in .pem .req and .p12 file.
        3. Verify whether subsystem certificate got exported in .pem .req and .p12 file.
        4. Verify whether audit_signing certificate got exported in .pem .req and .p12 file.
    """
    cert_file = '/tmp/ca_{}.pem'.format(cert_id)
    csr_file = '/tmp/ca_{}_csr.pem'.format(cert_id)
    p12_file = '/tmp/ca_{}.p12'.format(cert_id)
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
    else:
        instance = constants.CLONECA1_INSTANCE_NAME
    cert_export = 'pki-server subsystem-cert-export -i {} --cert-file {} --csr-file {} ' \
                  '--pkcs12-file {} --pkcs12-password {} ' \
                  'ca {}'.format(instance, cert_file, csr_file, p12_file,
                                 constants.CLIENT_PKCS12_PASSWORD, cert_id)
    signing_out = ansible_module.command(cert_export)
    for result in signing_out.values():
        if result['rc'] == 0:
            assert "Export complete" in result['stdout']
            for f in [cert_file, csr_file, p12_file]:
                exists = ansible_module.stat(path=f)
                for res in exists.values():
                    assert res['stat']['exists']
                    log.info("File {} exists.".format(f))
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()
    for f in [cert_file, csr_file, p12_file]:
        ansible_module.command('rm -rf {}'.format(f))


@pytest.mark.skipif("TOPOLOGY <= 3")
@pytest.mark.parametrize('cert_id', ('transport', 'storage', 'sslserver', 'subsystem',
                                     'audit_signing'))
def test_pki_server_subsystem_cert_export_clone_kra_certs(ansible_module, cert_id):
    """
    :id: bc037e47-a133-42e3-ade5-50924fe2d561
    :Title: Test pki-server subsystem-cert-export Clone KRA Transport certificate export
    :Description: Test pki-server subsystem-cert-export command, will export transport, storage,
                  SSLServer, Subsystem and Audit Signing certificate
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether transport certificate got exported in .pem .req and .p12 file.
        2. Verify whether storage certificate got exported in .pem .req and .p12 file.
        3. Verify whether sslserver certificate got exported in .pem .req and .p12 file.
        4. Verify whether subsystem certificate got exported in .pem .req and .p12 file.
        5. Verify whether audit_signing certificate got exported in .pem .req and .p12 file.
    """
    cert_file = '/tmp/kra_{}.pem'.format(cert_id)
    csr_file = '/tmp/kra_{}_csr.pem'.format(cert_id)
    p12_file = '/tmp/kra_{}.p12'.format(cert_id)
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
    else:
        instance = constants.CLONEKRA1_INSTANCE_NAME
    cert_export = 'pki-server subsystem-cert-export -i {} --cert-file {} --csr-file {} ' \
                  '--pkcs12-file {} --pkcs12-password {} ' \
                  'kra {}'.format(instance, cert_file, csr_file, p12_file,
                                  constants.CLIENT_PKCS12_PASSWORD, cert_id)
    signing_out = ansible_module.command(cert_export)
    for result in signing_out.values():
        if result['rc'] == 0:
            assert "Export complete" in result['stdout']
            for f in [cert_file, csr_file, p12_file]:
                exists = ansible_module.stat(path=f)
                for res in exists.values():
                    assert res['stat']['exists']
                    log.info("File {} exists.".format(f))
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()

    for f in [cert_file, csr_file, p12_file]:
        ansible_module.command('rm -rf {}'.format(f))


@pytest.mark.skipif("TOPOLOGY <= 3")
@pytest.mark.parametrize('cert_id', ('signing', 'sslserver', 'subsystem', 'audit_signing'))
def test_pki_server_subsystem_cert_export_clone_ocsp_certs(ansible_module, cert_id):
    """
    :id: 21a4f700-68ef-4d1d-8183-d9d5d9ba4d7d
    :Title: Test pki-server subsystem-cert-export Clone OCSP Signing certificate export
    :Description: Test pki-server subsystem-cert-export command, will export signing,
                  SSLServer, Subsystem and Audit Signing certificate
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether signing certificate got exported in .pem .req and .p12 file.
        2. Verify whether sslserver certificate got exported in .pem .req and .p12 file.
        3. Verify whether subsystem certificate got exported in .pem .req and .p12 file.
        4. Verify whether audit_signing certificate got exported in .pem .req and .p12 file.
    """
    cert_file = '/tmp/ocsp_{}.pem'.format(cert_id)
    csr_file = '/tmp/ocsp_{}_csr.pem'.format(cert_id)
    p12_file = '/tmp/ocsp_{}.p12'.format(cert_id)
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
    else:
        instance = constants.CLONEOCSP1_INSTANCE_NAME
    cert_export = 'pki-server subsystem-cert-export -i {} --cert-file {} --csr-file {} ' \
                  '--pkcs12-file {} --pkcs12-password {} ' \
                  'ocsp {}'.format(instance, cert_file, csr_file, p12_file,
                                   constants.CLIENT_PKCS12_PASSWORD, cert_id)
    signing_out = ansible_module.command(cert_export)
    for result in signing_out.values():
        if result['rc'] == 0:
            assert "Export complete" in result['stdout']
            for f in [cert_file, csr_file, p12_file]:
                exists = ansible_module.stat(path=f)
                for res in exists.values():
                    assert res['stat']['exists']
                    log.info("File {} exists.".format(f))
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()
    for f in [cert_file, csr_file, p12_file]:
        ansible_module.command('rm -rf {}'.format(f))


@pytest.mark.skipif("TOPOLOGY <= 3")
@pytest.mark.parametrize('cert_id', ('signing', 'sslserver', 'subsystem', 'audit_signing'))
def test_pki_server_subsystem_cert_export_clone_tks_sslserver(ansible_module, cert_id):
    """
    :id: 72fd03d8-8db2-4f9e-973a-34e97656eeea
    :Title: Test pki-server subsystem-cert-export Clone tks sslserver certificate export
    :Description: Test pki-server subsystem-cert-export command, will export signing,
                  SSLServer, Subsystem and Audit Signing certificate
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether signing certificate got exported in .pem .req and .p12 file.
        2. Verify whether sslserver certificate got exported in .pem .req and .p12 file.
        3. Verify whether subsystem certificate got exported in .pem .req and .p12 file.
        4. Verify whether audit_signing certificate got exported in .pem .req and .p12 file.
    """
    cert_file = '/tmp/tks_{}.pem'.format(cert_id)
    csr_file = '/tmp/tks_{}_csr.pem'.format(cert_id)
    p12_file = '/tmp/tks_{}.p12'.format(cert_id)
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
    else:
        instance = constants.TKS_INSTANCE_NAME
    cert_export = 'pki-server subsystem-cert-export -i {} --cert-file {} --csr-file {} ' \
                  '--pkcs12-file {} --pkcs12-password {} ' \
                  'tks {}'.format(instance, cert_file, csr_file, p12_file,
                                  constants.CLIENT_PKCS12_PASSWORD, cert_id)
    signing_out = ansible_module.command(cert_export)
    for result in signing_out.values():
        if result['rc'] == 0:
            assert "Export complete" in result['stdout']
            for f in [cert_file, csr_file, p12_file]:
                exists = ansible_module.stat(path=f)
                for res in exists.values():
                    assert res['stat']['exists']
                    log.info("File {} exists.".format(f))
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()

    for f in [cert_file, csr_file, p12_file]:
        ansible_module.command('rm -rf {}'.format(f))


@pytest.mark.skipif("TOPOLOGY <= 3")
@pytest.mark.parametrize('cert_id', ('signing', 'ocsp_signing', 'sslserver',
                                     'subsystem', 'audit_signing'))
def test_pki_server_subsystem_cert_export_subca_signing(ansible_module, cert_id):
    """
    :id: 8694fa09-78fe-4938-8306-db11b329ccf3
    :Title: Test pki-server subsystem-cert-export Sub CA Audit Signing certificate export
    :Description: Test pki-server subsystem-cert-export command, will export signing, ocsp_signing,
                  SSLServer, Subsystem and Audit Signing certificate
    :Requirement: Pki Server Subsystem
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether signing certificate got exported in .pem .req and .p12 file.
        2. Verify whether ocsp_signing certificate got exported in .pem .req and .p12 file.
        3. Verify whether sslserver certificate got exported in .pem .req and .p12 file.
        4. Verify whether subsystem certificate got exported in .pem .req and .p12 file.
        5. Verify whether audit_signing certificate got exported in .pem .req and .p12 file.
    """
    cert_file = '/tmp/subca_{}.pem'.format(cert_id)
    csr_file = '/tmp/subca_{}_csr.pem'.format(cert_id)
    p12_file = '/tmp/subca_{}.p12'.format(cert_id)
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
    else:
        instance = constants.SUBCA1_INSTANCE_NAME
    cert_export = 'pki-server subsystem-cert-export -i {} --cert-file {} --csr-file {} ' \
                  '--pkcs12-file {} --pkcs12-password {} ' \
                  'ca {}'.format(instance, cert_file, csr_file, p12_file,
                                 constants.CLIENT_PKCS12_PASSWORD, cert_id)
    signing_out = ansible_module.command(cert_export)
    for result in signing_out.values():
        if result['rc'] == 0:
            assert "Export complete" in result['stdout']
            for f in [cert_file, csr_file, p12_file]:
                exists = ansible_module.stat(path=f)
                for res in exists.values():
                    assert res['stat']['exists']
                    log.info("File {} exists.".format(f))
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()
    for f in [cert_file, csr_file, p12_file]:
        ansible_module.command('rm -rf {}'.format(f))


def test_pki_server_subsystem_cert_export_with_append(ansible_module):
    """
    :id: 1a91071b-7059-4f6a-b42b-cc2909384177
    :Title: Test pki-server subsystem-cert-export --append subsystem certificate to one file.
    :Description: Test pki-server subsystem-cert-export command, will export all subsystem
                  certificate to the one file.
    :Requirement: Pki Server Subsystem
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether CA subsystem certificate got exported in .p12 file.
        2. Verify whether KRA subsystem certificate got exported in .p12 file.
        3. Verify whether OCSP subsystem certificate got exported in .p12 file.
        4. Verify whether TKS subsystem certificate got exported in .p12 file.
        5. Verify whether TPS subsystem certificate got exported in .p12 file.
    """
    tmp_dir = '/tmp/subsystem_cert/'
    p12_file = '/tmp/all_subsystem.p12'

    client_cert_find = 'pki pkcs12-cert-find --pkcs12-file {} ' \
                       '--pkcs12-password {}'.format(p12_file, constants.CLIENT_PKCS12_PASSWORD)
    for subsystem in ['ca', 'kra']:  # TODO Remove after build , 'ocsp', 'tks', 'tps']:
        if TOPOLOGY == 1:
            instance = 'pki-tomcat'
        else:
            instance = eval("constants.{}_INSTANCE_NAME".format(subsystem.upper()))
        cert_export = 'pki-server subsystem-cert-export -i {} --pkcs12-file {} --pkcs12-password ' \
                      '{} {} subsystem --append'.format(instance, p12_file,
                                                        constants.CLIENT_PKCS12_PASSWORD, subsystem)
        signing_out = ansible_module.command(cert_export)
        for result in signing_out.values():
            if result['rc'] == 0:
                assert "Export complete" in result['stdout']
                for f in [p12_file]:
                    exists = ansible_module.stat(path=f)
                    for res in exists.values():
                        assert res['stat']['exists']
                        log.info("File {} exists.".format(f))
                log.info("Successfully run : {}".format(" ".join(result['cmd'])))
            else:
                log.error("Failed to run : {}".format(" ".join(result['cmd'])))
                pytest.skip()

    cert_find = ansible_module.command(client_cert_find)
    for result in cert_find.values():
        if result['rc'] == 0:
            for s in ['ca', 'kra']:  # TODO remove after build, 'ocsp', 'tks', 'tps']:
                if TOPOLOGY == 1:
                    instance = 'pki-tomcat'
                else:
                    instance = eval("constants.{}_INSTANCE_NAME".format(s.upper()))
                assert 'Friendly Name: subsystemCert cert-{}'.format(instance) in result['stdout']

    for f in [p12_file, tmp_dir]:
        ansible_module.command('rm -rf {}'.format(f))


def test_pki_server_subsystem_cert_export_with_pkcs12_password_file(ansible_module):
    """
    :id: 8d5d1f82-f932-471c-9428-768ca909cfdb
    :Title: Test pki-server subsystem-cert-export with pkcs12-password-file option.
    :Description: Test pki-server subsystem-cert-export command, will export subsystem certificate
                  in to the file using --pkcs12-password-file.
    :Requirement: Pki Server Subsystem
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether CA subsystem certificate got exported in .p12 file.
    """
    password_file = '/tmp/password.txt'
    p12_file = '/tmp/ca_subsystem.p12'
    ansible_module.shell('echo "{}" > {}'.format(constants.CLIENT_PKCS12_PASSWORD, password_file))

    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
    else:
        instance = constants.CA_INSTANCE_NAME
    cert_export = 'pki-server subsystem-cert-export -i {} --pkcs12-file {} ' \
                  '--pkcs12-password-file {} ca subsystem'.format(instance, p12_file, password_file)
    signing_out = ansible_module.command(cert_export)
    for result in signing_out.values():
        if result['rc'] == 0:
            assert "Export complete" in result['stdout']
            for f in [p12_file]:
                exists = ansible_module.stat(path=f)
                for res in exists.values():
                    assert res['stat']['exists']
                    log.info("File {} exists.".format(f))
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()

    client_cert_find = 'pki pkcs12-cert-find --pkcs12-file {} ' \
                       '--pkcs12-password-file {}'.format(p12_file, password_file)
    cert_find = ansible_module.command(client_cert_find)
    for result in cert_find.values():
        if result['rc'] == 0:
            if TOPOLOGY == 1:
                instance = 'pki-tomcat'
            else:
                instance = constants.CA_INSTANCE_NAME
            assert 'Friendly Name: subsystemCert cert-{}'.format(instance) in result['stdout']
    for f in [p12_file, password_file]:
        ansible_module.command('rm -rf {}'.format(f))


def test_pki_server_subsystem_cert_export_with_no_key_option(ansible_module):
    """
    :id: df0d4c33-c6f8-4c35-84e2-346338c9ae22
    :Title: Test pki-server subsystem-cert-export with no-key option.
    :Description: While run pki-server subsystem-cert-export with --no-key then it should not export
                  certificate key in to the file.
    :Requirement: Pki Server Subsystem
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :Expectedresults:
                1. It should not export private key in to the p12 file.
    """
    p12_file = '/tmp/ca_subsystem.p12'
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
    else:
        instance = constants.CA_INSTANCE_NAME
    cert_export = 'pki-server subsystem-cert-export -i {} --pkcs12-file {} --pkcs12-password ' \
                  '{} ca subsystem --no-key'.format(instance, p12_file,
                                                    constants.CLIENT_PKCS12_PASSWORD)
    signing_out = ansible_module.command(cert_export)
    for result in signing_out.values():
        if result['rc'] == 0:
            assert "Export complete" in result['stdout']
            for f in [p12_file]:
                exists = ansible_module.stat(path=f)
                for res in exists.values():
                    assert res['stat']['exists']
                    log.info("File {} exists.".format(f))
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()

    client_cert_find = 'pki pkcs12-cert-find --pkcs12-file {} ' \
                       '--pkcs12-password {}'.format(p12_file, constants.CLIENT_PKCS12_PASSWORD)
    cert_find = ansible_module.command(client_cert_find)
    for result in cert_find.values():
        if result['rc'] == 0:
            if TOPOLOGY == 1:
                instance = 'pki-tomcat'
            else:
                instance = constants.CA_INSTANCE_NAME
            assert 'Friendly Name: subsystemCert cert-{}'.format(instance) in result['stdout']
            assert 'Has Key: false'
    for f in [p12_file]:
        ansible_module.command('rm -rf {}'.format(f))


def test_pki_server_subsystem_cert_export_with_no_chain_option(ansible_module):
    """
    :id: 0ac1dfc3-e98d-43b0-b3ba-a95f78a1b741
    :Title: Test pki-server subsystem-cert-export with no-chain option.
    :Description: While run pki-server subsystem-cert-export with --no-chain then it should
                  not export certificate with chain.
    :Requirement: Pki Server Subsystem
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :Expectedresults:
                1. It should not export CA certificate in to the p12 file.
    """
    p12_file = '/tmp/ca_subsystem.p12'
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
    else:
        instance = constants.CA_INSTANCE_NAME
    cert_export = 'pki-server subsystem-cert-export -i {} --pkcs12-file {} --pkcs12-password ' \
                  '{} ca subsystem --no-chain'.format(instance, p12_file,
                                                      constants.CLIENT_PKCS12_PASSWORD)
    signing_out = ansible_module.command(cert_export)
    for result in signing_out.values():
        if result['rc'] == 0:
            assert "Export complete" in result['stdout']
            for f in [p12_file]:
                exists = ansible_module.stat(path=f)
                for res in exists.values():
                    assert res['stat']['exists']
                    log.info("File {} exists.".format(f))
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()

    client_cert_find = 'pki pkcs12-cert-find --pkcs12-file {} ' \
                       '--pkcs12-password {}'.format(p12_file, constants.CLIENT_PKCS12_PASSWORD)
    cert_find = ansible_module.command(client_cert_find)
    for result in cert_find.values():
        if result['rc'] == 0:
            if TOPOLOGY == 1:
                instance = 'pki-tomcat'
            else:
                instance = constants.CA_INSTANCE_NAME
            assert 'Friendly Name: subsystemCert cert-{}'.format(instance) in result['stdout']
            assert 'Has Key: true' in result['stdout']
            assert 'Nickname: CA Signing Certificate' not in result['stdout']
            assert 'Trust Flags: CT,C,C' not in result['stdout']
    for f in [p12_file]:
        ansible_module.command('rm -rf {}'.format(f))
