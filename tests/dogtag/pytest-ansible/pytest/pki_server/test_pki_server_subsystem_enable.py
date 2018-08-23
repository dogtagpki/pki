"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki-server subsystem cli commands needs to be tested:
#   pki-server subsystem-enable
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

import os
import random
import string
import sys
import time

import pytest

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

Topology = int(''.join(constants.CA_INSTANCE_NAME.split("-")[1]))


@pytest.mark.xfail(reason='BZ-1340718')
def test_pki_server_subsystem_enable_help(ansible_module):
    """
    :id: 7aca2cd6-ab26-455d-8aff-08115e64d94d
    :Title: Test pki-server subsystem-enable --help command
    :Description: test pki-server subsystem-enable --help command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :ExpectedResults: 
        1. Verify whether pki-server subsystem-enable --help command enables the subsystem
    """
    enable_help = ansible_module.command('pki-server subsystem-enable --help')
    for result in enable_help.values():
        if result['rc'] == 0:
            assert "Usage: pki-server subsystem-enable [OPTIONS] <subsystem ID>" in \
                   result['stdout']
            assert "-i, --instance <instance ID>    Instance ID (default: pki-tomcat)" in \
                   result['stdout']
            assert "-v, --verbose                   Run in verbose mode." in result['stdout']
            assert "--help                      Show help message." in result['stdout']
        else:
            pytest.xfail("Failed to run pki-server subsystem-enable --help command.")


def test_pki_server_subsystem_enable_ca(ansible_module):
    """
    :id: 0aba6d96-47be-46a8-a719-c0a0739011db
    :Title: Test pki-server subsystem-enable with CA subsystem
    :Description: test pki-server subsystem-enable command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults: 
        1. Verify whether pki-server subsystem-enable command enables the ca subsystem
    """
    cert_request = 'pki -d {} -c {} -h localhost -p {} client-cert-request ' \
                   '"UID=foo1,E=example.org"'.format(constants.NSSDB,
                                                     constants.CLIENT_DIR_PASSWORD,
                                                     constants.CA_HTTP_PORT)
    ca_out = ansible_module.command('pki-server subsystem-enable -i {} '
                                    'ca'.format(constants.CA_INSTANCE_NAME))
    for result in ca_out.values():
        if result['rc'] == 0:
            assert "Subsystem ID: ca" in result['stdout']
            assert "Instance ID: %s" % constants.CA_INSTANCE_NAME in result['stdout']
            assert "Enabled: True" in result['stdout']
            time.sleep(20)
            request_out = ansible_module.command(cert_request)
            for res in request_out.values():
                if res['rc'] == 0:
                    assert "Submitted certificate request" in res['stdout']
                    assert "Type: enrollment" in res['stdout']
                    assert "Request Status: pending" in res['stdout']
                    assert "Operation Result: success" in res['stdout']
                else:
                    pytest.xfail("Failed to run pki-server subsystem-enable command.")


@pytest.mark.parametrize('subsystem', ['kra', 'ocsp', 'tks', 'tps'])
def test_pki_server_subsystem_enable_other_systems(ansible_module, subsystem):
    """
    :id: 0f6b9e9e-7e2b-4307-8bc3-d7f99fa8d1b4
    :Title: Test pki-server subsystem-enable with KRA subsystem
    :Description: test pki-server subsystem-enable command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults: Verify whether pki-server subsystem-enable command enables the kra subsystem
    """
    instance = eval("constants.{}_INSTANCE_NAME".format(subsystem.upper()))
    cmd_out = ansible_module.command('pki-server subsystem-enable '
                                     '-i {} {}'.format(instance, subsystem))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Subsystem ID: {}".format(subsystem) in result['stdout']
            assert "Instance ID: " + instance in result['stdout']
            assert "Enabled: True" in result['stdout']
        else:
            pytest.xfail("Failed to enable subsystem.")


@pytest.mark.skipif("Topology <= 3")
def test_pki_server_subsystem_enable_clone_ca(ansible_module):
    """
    :id: a1f12120-b798-482a-ab9b-90d4f94c9e84
    :Title: Test pki-server subsystem-enable with Clone CA subsystem
    :Description: test pki-server subsystem-enable command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server subsystem-enable command enables the clone ca subsystem
    """
    cert_request = 'pki -d {} -c {} -h localhost -p {} client-cert-request ' \
                   '"UID=foo1,E=example.org"'.format(constants.NSSDB,
                                                     constants.CLIENT_DIR_PASSWORD,
                                                     constants.CLONECA1_HTTP_PORT)

    ca_output = ansible_module.command('pki-server subsystem-enable '
                                       '-i {} ca'.format(constants.CLONECA1_INSTANCE_NAME))
    for result in ca_output.values():
        if result['rc'] == 0:
            assert "Subsystem ID: ca" in result['stdout']
            assert "Instance ID: %s" % constants.CLONECA1_INSTANCE_NAME in result['stdout']
            assert "Enabled: True" in result['stdout']
            stat_out = ansible_module.command(cert_request)
            for res in stat_out.values():
                if res['rc'] == 0:
                    assert "Submitted certificate request" in result['stdout']
                    assert "Type: enrollment" in result['stdout']
                    assert "Request Status: pending" in result['stdout']
                    assert "Operation Result: success" in result['stdout']
        else:
            pytest.xfail("Failed to run pki-server subsystem-enable command.")


@pytest.mark.skipif("Topology <= 3")
def test_pki_server_subsystem_enable_clone_kra(ansible_module):
    """
    :id: eca4b6c8-7dfc-42e8-9c7a-9a3d67472994
    :Title: Test pki-server subsystem-enable with Clone KRA subsystem
    :Description: test pki-server subsystem-enable command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server subsystem-enable command enables the clone kra subsystem
    """
    instance = constants.CLONEKRA1_INSTANCE_NAME
    subsystem = 'kra'
    cmd_out = ansible_module.command('pki-server subsystem-enable '
                                     '-i {} {}'.format(instance, subsystem))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Subsystem ID: kra" in result['stdout']
            assert "Instance ID: " + instance in result['stdout']
            assert "Enabled: True" in result['stdout']
        else:
            pytest.xfail("Failed to enable subsystem.")


@pytest.mark.skipif("Topology <= 3")
def test_pki_server_subsystem_enable_clone_ocsp(ansible_module):
    """
    :id: e782a486-5656-4e0b-bc16-784603bd1260
    :Title: Test pki-server subsystem-enable with Clone OCSP subsystem
    :Description: test pki-server subsystem-enable command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server subsystem-enable command enables the clone ocsp subsystem
    """
    instance = constants.CLONEOCSP1_INSTANCE_NAME
    subsystem = 'ocsp'
    cmd_out = ansible_module.command('pki-server subsystem-enable '
                                     '-i {} {}'.format(instance, subsystem))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Subsystem ID: ocsp" in result['stdout']
            assert "Instance ID: " + instance in result['stdout']
            assert "Enabled: True" in result['stdout']
        else:
            pytest.xfail("Failed to enable subsystem.")


@pytest.mark.skipif("Topology <= 3")
def test_pki_server_subsystem_enable_clone_tks(ansible_module):
    """
    :id: 8dcbdb47-1431-40ab-ae51-be434f620d2d
    :Title: Test pki-server subsystem-enable with Clone TKS subsystem
    :Description: test pki-server subsystem-enable command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server subsystem-enable command enables the clone tks subsystem
    """
    instance = constants.CLONETKS1_INSTANCE_NAME
    subsystem = 'tks'
    cmd_out = ansible_module.command('pki-server subsystem-enable '
                                     '-i {} {}'.format(instance, subsystem))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Subsystem ID: ocsp" in result['stdout']
            assert "Instance ID: " + instance in result['stdout']
            assert "Enabled: True" in result['stdout']
        else:
            pytest.xfail("Failed to enable subsystem.")


@pytest.mark.skipif("Topology <= 3")
def test_pki_server_subsystem_enable_clone_subca(ansible_module):
    """
    :id: a1508386-07c0-4920-b758-e14cdfaae646
    :Title: Test pki-server subsystem-enable with Clone CA subsystem
    :Description: test pki-server subsystem-enable command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server subsystem-enable command enables the subca subsystem
    """
    cert_request = 'pki -d {} -c {} -h localhost -p {} client-cert-request ' \
                   '"UID=foo1,E=example.org"'.format(constants.NSSDB,
                                                     constants.CLIENT_DIR_PASSWORD,
                                                     constants.SUBCA_HTTP_PORT)

    ca_output = ansible_module.command('pki-server subsystem-enable '
                                       '-i {} ca'.format(constants.SUBCA_INSTANCE_NAME))
    for result in ca_output.values():
        if result['rc'] == 0:
            assert "Subsystem ID: ca" in result['stdout']
            assert "Instance ID: %s" % constants.SUBCA_INSTANCE_NAME in result['stdout']
            assert "Enabled: True" in result['stdout']
            stat_out = ansible_module.command(cert_request)
            for res in stat_out.values():
                if res['rc'] == 0:
                    assert "Submitted certificate request" in result['stdout']
                    assert "Type: enrollment" in result['stdout']
                    assert "Request Status: pending" in result['stdout']
                    assert "Operation Result: success" in result['stdout']
        else:
            pytest.xfail("Failed to run pki-server subsystem-enable command.")


def test_pki_server_subsystem_enable_invalid_instance(ansible_module):
    """
    :id: 6be6c100-d4b5-44ec-9824-920e7362a719
    :Title: Test pki-server subsystem-enable with invalid instance
    :Description: test pki-server subsystem-enable command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :ExpectedResults:
        1. Verify whether pki-server subsystem-enable command throws error when non existing
        instance name is supplied.
    """
    junk_instance = ''.join(random.choice(string.ascii_uppercase + string.digits)
                            for _ in range(10))
    ca_out = ansible_module.command('pki-server subsystem-enable -i {} ca'.format(junk_instance))
    for result in ca_out.values():
        if result['rc'] >= 1:
            assert "ERROR: Invalid instance " + junk_instance in result['stdout']
        else:
            pytest.xfail("Failed: Disabled the Invalid subsystem.")


@pytest.mark.xfail(reason="BZ=1356609")
def test_pki_server_subsystem_enable_invalid_subsystemType(ansible_module):
    """
    :id: 485e589a-8f7f-4c81-b652-a4ca8b05b7da
    :Title: Test pki-server subsystem-enable with invalid subsystem type
    :Description: test pki-server subsystem-enable command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server subsystem-enable command throws error when non existing
        subsystem type is supplied.
    """
    junk_subsystemType = ''.join(random.choice(string.ascii_uppercase + string.digits)
                                 for _ in range(10))
    subsystem_enable = 'pki-server subsystem-enable -i {} ' \
                       '{}'.format(constants.CA_INSTANCE_NAME, junk_subsystemType)
    ca_out = ansible_module.command(subsystem_enable)
    for result in ca_out.values():
        if result['rc'] >= 1:
            assert "ERROR: No {} subsystem in " \
                   "instance {}".format(junk_subsystemType,
                                        constants.CA_INSTANCE_NAME) in result['stderr']
        else:
            pytest.xfail("Failed: Disabled the subsystem with invalid subsystem type.")


def test_pki_server_subsystem_enable_enabled_subsystem(ansible_module):
    """
    :id: 79ff6e10-87fa-4d34-a495-870c5fc0d8a8
    :Title: Test pki-server subsystem-enable with enabled subsystem
    :Description: test pki-server subsystem-enable command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server subsystem-enable command throws error when trying to enable
        the enabled subsystem.
    """
    ansible_module.command('pki-server subsystem-enable '
                           '-i {} ca'.format(constants.CA_INSTANCE_NAME))
    ca_out = ansible_module.command('pki-server subsystem-enable '
                                    '-i {} ca'.format(constants.CA_INSTANCE_NAME))
    for result in ca_out.values():
        if result['stdout'] == 0:
            assert 'Subsystem "ca" is already enabled' in result['stdout']
            assert "Subsystem ID: ca" in result['stdout']
            assert "Instance ID: %s" % constants.CA_INSTANCE_NAME in result['stdout']
            assert "Enabled: True" in result['stdout']
        else:
            pytest.xfail("Failed to enable the already enabled subsystem")
