"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki-server subsystem cli commands needs to be tested:
#   pki-server subsystem-cert
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
TOPOLOGY = int(constants.CA_INSTANCE_NAME.split("-")[-2])
log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)


# @pytest.mark.xfail(reason='BZ-1340718')
def test_pki_server_subsystem_cert_find_help(ansible_module):
    """
    :id: 23181198-bd7d-410d-8f36-d5179440956a
    :Title: Test pki-server subsystem-cert-find --help command
    :Description: test pki-server subsystem-cert-find command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults: Verify whether pki-server subsystem-cert-find command shows help options.
    """
    find_out = ansible_module.command('pki-server subsystem-cert-find --help')
    for result in find_out.values():
        if result['rc'] == 0:
            assert "Usage: pki-server subsystem-cert-find [OPTIONS] <subsystem ID>" in \
                   result['stdout']
            assert "-i, --instance <instance ID>    Instance ID (default: pki-tomcat)." in \
                   result['stdout']
            assert "--show-all                  Show all attributes." in result['stdout']
            assert "-v, --verbose                   Run in verbose mode." in result['stdout']
            assert "--help                      Show help message." in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()


def test_pki_server_subsystem_cert(ansible_module):
    """
    :id: e639c88a-c9e5-45b8-9c54-1e6aed722b29
    :Title: Test pki-server subsystem-cert command 
    :Description: test pki-server subsystem-cert command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :ExpectedResults: 
        1. Verify whether pki-server subsystem-cert command shows subsystem-cert-find,
        subsystem-cert-show, subsystem-cert-export, subsystem-cert-update commands.
    """
    find_out = ansible_module.command('pki-server subsystem-cert')
    for result in find_out.values():
        if result['rc'] == 0:
            assert "subsystem-cert-find           Find subsystem certificates" in result['stdout']
            assert "subsystem-cert-show           Show subsystem certificate" in result['stdout']
            assert "subsystem-cert-export         Export subsystem certificate" in result['stdout']
            assert "subsystem-cert-update         Update subsystem certificate" in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))

        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()


def test_pki_server_subsystem_cert_find_ca(ansible_module):
    """
    :id: 081fe0d7-a747-4d68-8331-261efcf2c7ea
    :Title: Test pki-server subsystem-cert-find ca command.
    :Description: test pki-server subsystem-cert-find command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults: 
        Verify whether pki-server subsystem-cert-find command lists the ca subsystem certificates.
    """
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
    else:
        instance = constants.CA_INSTANCE_NAME
    find_out = ansible_module.command('pki-server subsystem-cert-find '
                                      '-i {} ca'.format(instance))
    for result in find_out.values():
        if result['rc'] == 0:
            assert "entries matched" in result['stdout']
            assert "Cert ID: signing" in result['stdout']
            assert "Nickname: caSigningCert cert-" + instance + " CA" in result['stdout']
            assert "Token: internal" in result['stdout']
            assert "Cert ID: ocsp_signing" in result['stdout']
            assert "Nickname: ocspSigningCert cert-" + instance + " CA" in result['stdout']
            assert "Token: internal" in result['stdout']
            assert "Cert ID: sslserver" in result['stdout']
            assert "Nickname: Server-Cert cert-" + instance in result['stdout']
            assert "Token: internal" in result['stdout']
            assert "Cert ID: subsystem" in result['stdout']
            assert "Nickname: subsystemCert cert-" + instance in result['stdout']
            assert "Token: internal" in result['stdout']
            assert "Cert ID: audit_signing" in result['stdout']
            assert "Nickname: auditSigningCert cert-" + instance + " CA" in result['stdout']
            assert "Token: internal" in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()


def test_pki_server_subsystem_cert_find_kra(ansible_module):
    """
    :id: fa55c65e-c2d1-4138-b8b5-c2857938cca7
    :Title: Test pki-server subsystem-cert-find kra command
    :Description: test pki-server subsystem-cert-find command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults: 
        1. Verify whether pki-server subsystem-cert-find command lists the kra 
            subsystem certificates.
    """
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
    else:
        instance = constants.KRA_INSTANCE_NAME
    kra_out = ansible_module.command('pki-server subsystem-cert-find '
                                     '-i {} kra'.format(instance))

    for result in kra_out.values():
        if result['rc'] == 0:
            assert "entries matched" in result['stdout']
            assert "Cert ID: transport" in result['stdout']
            assert "Nickname: transportCert cert-" + instance + " KRA" in result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            assert "Cert ID: storage" in result['stdout']
            assert "Nickname: storageCert cert-" + instance + " KRA" in result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            assert "Cert ID: sslserver" in result['stdout']
            assert "Nickname: Server-Cert cert-" + instance in result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            assert "Cert ID: subsystem" in result['stdout']
            assert "Nickname: subsystemCert cert-" + instance in result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            assert "Cert ID: audit_signing" in result['stdout']
            assert "Nickname: auditSigningCert cert-" + instance + " KRA" in result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()


def test_pki_server_subsystem_cert_find_ocsp(ansible_module):
    """
    :id: 28cbd84b-6817-47dc-bfea-aaec6d07a95e
    :Title: Test pki-server subsystem-cert-find ocsp command
    :Description: test pki-server subsystem-cert-find command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        Verify whether pki-server subsystem-cert-find command lists the OCSP subsystem certificates.
    """
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
    else:
        instance = constants.OCSP_INSTANCE_NAME
    ocsp_out = ansible_module.command('pki-server subsystem-cert-find '
                                      '-i {} ocsp'.format(instance))
    for result in ocsp_out.values():
        if result['rc'] == 0:
            assert "entries matched" in result['stdout']
            assert "Cert ID: signing" in result['stdout']
            assert "Nickname: ocspSigningCert cert-" + instance + " OCSP" in result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            assert "Cert ID: sslserver" in result['stdout']
            assert "Nickname: Server-Cert cert-" + instance in result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            assert "Cert ID: subsystem" in result['stdout']
            assert "Nickname: subsystemCert cert-" + instance in result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            assert "Cert ID: audit_signing" in result['stdout']
            assert "Nickname: auditSigningCert cert-" + instance + " OCSP" in result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()


def test_pki_server_subsystem_cert_find_tks(ansible_module):
    """
    :id: b8d08e42-cc2e-453b-b7c1-72c1356c4e04
    :Title: Test pki-server subsystem-cert-find tks command
    :Description: test pki-server subsystem-cert-find command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults: 
        1. Verify whether pki-server subsystem-cert-find command lists the tks 
           subsystem certificates.
    """
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
    else:
        instance = constants.TKS_INSTANCE_NAME
    tks_out = ansible_module.command('pki-server subsystem-cert-find '
                                     '-i {} tks'.format(instance))
    for result in tks_out.values():
        if result['rc'] == 0:
            assert "entries matched" in result['stdout']
            assert "Cert ID: sslserver" in result['stdout']
            assert "Nickname: Server-Cert cert-" + instance in result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            assert "Cert ID: subsystem" in result['stdout']
            assert "Nickname: subsystemCert cert-" + instance in result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            assert "Cert ID: audit_signing" in result['stdout']
            assert "Nickname: auditSigningCert cert-" + instance + " TKS" in result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()


def test_pki_server_subsystem_cert_find_tps(ansible_module):
    """
    :id: 81ddf075-8456-4515-ae77-536ce15dd8b8
    :Title: Test pki-server subsystem-cert-find tps command
    :Description: test pki-server subsystem-cert-find tps command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults: 
        1. Verify whether pki-server subsystem-cert-find command lists the tps 
            subsystem certificates.
    """
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
    else:
        instance = constants.TPS_INSTANCE_NAME
    tps_out = ansible_module.command('pki-server subsystem-cert-find '
                                     '-i {} tps'.format(instance))
    for result in tps_out.values():
        if result['rc'] == 0:
            assert "entries matched" in result['stdout']
            assert "Cert ID: sslserver" in result['stdout']
            assert "Nickname: Server-Cert cert-" + instance in result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            assert "Cert ID: subsystem" in result['stdout']
            assert "Nickname: subsystemCert cert-" + instance in result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            assert "Cert ID: audit_signing" in result['stdout']
            assert "Nickname: auditSigningCert cert-" + instance + " TPS" in result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()


@pytest.mark.skipif("TOPOLOGY <= 3")
def test_pki_server_subsystem_cert_find_clone_ca(ansible_module):
    """
    :id: 520d1ea5-b1db-4adf-afc9-b4b3e886093f
    :Title: Test pki-server subsystem-cert-find clone ca command
    :Description: test pki-server subsystem-cert-find command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem 
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults: 
        1. Verify whether pki-server subsystem-cert-find command lists the ca subsystem 
        certificates.
    """
    clone_ca = ansible_module.command('pki-server subsystem-cert-find '
                                      '-i {} ca'.format(constants.CLONECA1_INSTANCE_NAME))
    for result in clone_ca.values():
        if result['rc'] == 0:
            assert "entries matched" in result['stdout']
            assert "Cert ID: signing" in result['stdout']
            assert "Nickname: caSigningCert cert-" + constants.CLONECA1_INSTANCE_NAME + " CA" in \
                   result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            assert "Cert ID: ocsp_signing" in result['stdout']
            assert "Nickname: ocspSigningCert cert-" + constants.CLONECA1_INSTANCE_NAME + " CA" \
                   in result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            assert "Cert ID: sslserver" in result['stdout']
            assert "Nickname: Server-Cert cert-" + constants.CLONECA1_INSTANCE_NAME in \
                   result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            assert "Cert ID: subsystem" in result['stdout']
            assert "Nickname: subsystemCert cert-" + constants.CLONECA1_INSTANCE_NAME in \
                   result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            assert "Cert ID: audit_signing" in result['stdout']
            assert "Nickname: auditSigningCert cert-" + constants.CLONECA1_INSTANCE_NAME + " CA" \
                   in result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
        else:
            pytest.skip("Failed to run pki-server subsystem-cert-find command..!!")


@pytest.mark.skipif("TOPOLOGY <= 3")
def test_pki_server_subsystem_cert_find_clone_kra(ansible_module):
    """
    :id: 1aec4676-7707-4d9c-a990-b9b80b2d2236
    :Title: Test pki-server subsystem-find clone KRA command.
    :Description: test pki-server subsystem-cert-find command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults: 
        1. Verify whether pki-server subsystem-cert-find command lists the clone 
            kra subsystem certificates.
    """
    kra_out = ansible_module.command('pki-server subsystem-cert-find '
                                     '-i {} kra'.format(constants.CLONEKRA1_INSTANCE_NAME))
    for result in kra_out.values():
        if result['rc'] == 0:
            assert "entries matched" in result['stdout']
            assert "Cert ID: transport" in result['stdout']
            assert "Nickname: transportCert cert-" + constants.CLONEKRA1_INSTANCE_NAME + " KRA" \
                   in result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            assert "Cert ID: storage" in result['stdout']
            assert "Nickname: storageCert cert-" + constants.CLONEKRA1_INSTANCE_NAME + " KRA" in \
                   result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            assert "Cert ID: sslserver" in result['stdout']
            assert "Nickname: Server-Cert cert-" + constants.CLONEKRA1_INSTANCE_NAME in \
                   result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            assert "Cert ID: subsystem" in result['stdout']
            assert "Nickname: subsystemCert cert-" + constants.CLONEKRA1_INSTANCE_NAME in \
                   result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            assert "Cert ID: audit_signing" in result['stdout']
            assert "Nickname: auditSigningCert cert-" + constants.CLONEKRA1_INSTANCE_NAME + " KRA" in \
                   result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']

        else:
            pytest.skip("Failed to run pki-server subsystem-cert-find command..!!")


@pytest.mark.skipif("TOPOLOGY <= 3")
def test_pki_server_subsystem_cert_find_clone_ocsp(ansible_module):
    """
    :id: 9176c1b4-5703-4396-8c58-d3048467f6cb
    :Title: Test pki-server subsystem-cert-find clone ocsp command
    :Description: test pki-server subsystem-cert-find command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults: 
        1. Verify whether pki-server subsystem-cert-find command lists the clone OCSP 
           subsystem certificates.
    """
    ocsp_out = ansible_module.command('pki-server subsystem-cert-find '
                                      '-i {} ocsp'.format(constants.CLONEOCSP1_INSTANCE_NAME))
    for result in ocsp_out.values():
        if result['rc'] == 0:
            assert "entries matched" in result['stdout']
            assert "Cert ID: signing" in result['stdout']
            assert "Nickname: ocspSigningCert cert-" + constants.CLONEOCSP1_INSTANCE_NAME + " OCSP" \
                   in result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            assert "Cert ID: sslserver" in result['stdout']
            assert "Nickname: Server-Cert cert-" + constants.CLONEOCSP1_INSTANCE_NAME in \
                   result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            assert "Cert ID: subsystem" in result['stdout']
            assert "Nickname: subsystemCert cert-" + constants.CLONEOCSP1_INSTANCE_NAME in \
                   result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            assert "Cert ID: audit_signing" in result['stdout']
            assert "Nickname: auditSigningCert cert-" + \
                   constants.CLONEOCSP1_INSTANCE_NAME + " OCSP" in result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
        else:
            pytest.skip("Failed to run pki-server subsystem-cert-find command..!!")


@pytest.mark.skipif("TOPOLOGY <= 3")
def test_pki_server_subsystem_cert_find_clone_tks(ansible_module):
    """
    :id: d454a71c-2562-4dfc-8434-65c9cfa5390e
    :Title: Test pki-server subystem-cert-find clone tks command
    :Description: test pki-server subsystem-cert-find command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem 
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults: 
        1. Verify whether pki-server subsystem-cert-find command lists the clone tks 
           subsystem certificates.
    """
    clone_tks = ansible_module.command('pki-server subsystem-cert-find '
                                       '-i {} tks'.format(constants.CLONETKS1_INSTANCE_NAME))
    for result in clone_tks.values():
        if result['rc'] == 0:
            assert "entries matched" in result['stdout']
            assert "Cert ID: sslserver" in result['stdout']
            assert "Nickname: Server-Cert cert-" + constants.CLONEiTKS1_INSTANCE_NAME in \
                   result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            assert "Cert ID: subsystem" in result['stdout']
            assert "Nickname: subsystemCert cert-" + constants.CLONETKS1_INSTANCE_NAME in \
                   result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            assert "Cert ID: audit_signing" in result['stdout']
            assert "Nickname: auditSigningCert cert-" + \
                   constants.CLONETKS1_INSTANCE_NAME + " TKS" in result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
        else:
            pytest.skip("Failed to run pki-server subsystem-cert-find command..!!")


@pytest.mark.skipif("TOPOLOGY <= 3")
def test_pki_server_subsystem_cert_find_subca(ansible_module):
    """
    :id: 68592172-ec7a-44c6-ad62-5779442d25c6
    :Title: Test pki-server subsystem-cert-find subca command
    :Description: test pki-server subsystem-cert-find command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server subsystem-cert-find command lists the subca subsystem
        certificates.
    """
    ca_out = ansible_module.command('pki-server subsystem-cert-find '
                                    '-i {} ca'.format(constants.SUBCA1_INSTANCE_NAME))
    for result in ca_out.values():
        if result['rc'] == 0:
            assert "entries matched" in result['stdout']
            assert "Cert ID: signing" in result['stdout']
            assert "Nickname: caSigningCert cert-" + constants.SUBCA1_INSTANCE_NAME + " CA" in \
                   result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            assert "Cert ID: ocsp_signing" in result['stdout']
            assert "Nickname: ocspSigningCert cert-" + constants.SUBCA1_INSTANCE_NAME + " CA" in \
                   result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            assert "Cert ID: sslserver" in result['stdout']
            assert "Nickname: Server-Cert cert-" + constants.SUBCA1_INSTANCE_NAME in \
                   result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            assert "Cert ID: subsystem" in result['stdout']
            assert "Nickname: subsystemCert cert-" + constants.SUBCA1_INSTANCE_NAME in \
                   result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
            assert "Cert ID: audit_signing" in result['stdout']
            assert "Nickname: auditSigningCert cert-" + constants.SUBCA1_INSTANCE_NAME + " CA" in \
                   result['stdout']
            assert "Token: Internal Key Storage Token" in result['stdout']
        else:
            pytest.skip("Failed to run pki-server subsystem-cert-find command..!!")
