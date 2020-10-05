"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI SERVER  CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki-server cli commands needs to be tested:
#   pki-server
#   pki-server ca
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

from subprocess import CalledProcessError
import logging
import sys

import pytest
from pki.testlib.common import utils

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)


def test_pki_server(ansible_module):
    """
    :id: 6f671d63-283c-4599-9289-6977529b6634
    :Title: Test pki-server command
    :CaseComponent: \-
    :Requirement: Pki Server CA
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults: 
        1. Verify whether pki-server command shows ca, kra, ocsp, tks, tps, instance, 
        subsystem, migrate, nuxwdog commands
    """

    try:
        server_out = ansible_module.shell('pki-server --help')
        for result in server_out.values():
            assert "-v, --verbose                Run in verbose mode." in result['stdout']
            assert "--debug                  Show debug messages." in result['stdout']
            assert "--help                   Show help message." in result['stdout']
            assert "ca                            CA management commands" in result['stdout']
            assert "kra                           KRA management commands" in result['stdout']
            assert "ocsp                          OCSP management commands" in result['stdout']
            assert "tks                           TKS management commands" in result['stdout']
            assert "tps                           TPS management commands" in result['stdout']
            assert "instance                      Instance management commands" in result['stdout']
            assert "subsystem                     Subsystem management commands" in result['stdout']
            assert "migrate                       Migrate system" in result['stdout']
            assert "nuxwdog                       Nuxwdog related commands" in result['stdout']
    except CalledProcessError:
        pytest.fail("Failed to run pki-server command.")


def test_pki_server_junk(ansible_module):
    """
    :id: 140f53a4-d3ed-4d21-bc4e-996a6a1232a6
    :Title: Test pki-server with junk sub-command
    :Requirement: test pki-server  command
    :CaseComponent: \-
    :Requirement: Pki Server CA
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults: 
        1. Verify whether pki-server command fails with junk option
    """
    junk = utils.get_random_string(len=10)
    junk_out = ansible_module.shell('pki-server {}'.format(junk))
    for result in junk_out.values():
        if result['rc'] > 0:
            assert 'ERROR: Invalid module "{}".'.format(junk) in result['stderr']
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail("Failed to run pki-server {} option.".format(junk))


@pytest.mark.parametrize('subsystems', ['ca', 'kra', 'ocsp', 'tks', 'tps'])
def test_pki_server_ca(ansible_module, subsystems):
    """
    :id: 2bb0595f-e25c-4ddf-890b-b2e4a3e0323b
    :Title: Test pki-server ca command
    :Description: Test pki-server ca command
    :Requirement: Pki Server CA
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :ExpectedResults: 
        1. Verify whether pki-server ca command shows ca-cert, ca-clone commands
    """
    try:
        pki_ca_out = ansible_module.shell('pki-server {}'.format(subsystems))
        for result in pki_ca_out.values():
            if subsystems == 'ca':
                assert "ca-cert                       CA certificates management commands" in \
                       result['stdout']
                assert "ca-clone                      CA clone management commands" in \
                       result['stdout']
                assert "ca-audit                      Audit management commands" in result['stdout']
            elif subsystems == 'kra':
                assert "kra-clone                     KRA clone management commands" in \
                       result['stdout']
                assert "kra-db                        KRA database management commands" in \
                       result['stdout']
                assert "kra-audit                     Audit management commands" in result['stdout']
            elif subsystems == 'ocsp':
                assert "ocsp-clone                    OCSP clone management commands" in \
                       result['stdout']
                assert "ocsp-audit                    Audit management commands" in result['stdout']
            elif subsystems == 'tks':
                assert "tks-clone                     TKS clone management commands" in \
                       result['stdout']
                assert "tks-audit                     Audit management commands" in result['stdout']
            elif subsystems == 'tps':
                assert "tps-clone                     TPS clone management commands" in \
                       result['stdout']
                assert "tps-db                        TPS database management commands" in \
                       result['stdout']
                assert "tps-audit                     Audit management commands" in result['stdout']
    except CalledProcessError:
        pytest.fail("Failed to run pki-server ca command.")


@pytest.mark.parametrize('subsystem', ['ca', 'kra', 'ocsp', 'tks', 'tps'])
def test_pki_server_with_junk(ansible_module, subsystem):
    """
    :id: 37df246a-68bf-4cf5-893e-a3d17b033968
    :Title: Test pki-server with junk subsystem command.
    :Description: Test pki-server with junk subsystem command
    :Requirement: Pki Server CA
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1.
    :ExpectedResults:
        1. Verify whether pki-server command fails with junk option
    """
    junk = utils.get_random_string(len=50)
    junk_output = ansible_module.shell('pki-server {} {}'.format(subsystem, junk))
    for result in junk_output.values():
        if result['rc'] >= 1:
            assert 'ERROR: Invalid module "{}".'.format(junk) in result['stderr']
            log.info('Successfully ran the command {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail("Failed to run pki-server with junk option.")
