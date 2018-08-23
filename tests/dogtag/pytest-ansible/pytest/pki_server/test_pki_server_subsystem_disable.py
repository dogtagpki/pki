"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki-server subsystem cli commands needs to be tested:
#   pki-server subsystem-disable
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

import random
import string
import sys

import os
import pytest

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

Topology = int(''.join(constants.CA_INSTANCE_NAME.split("-")[1]))


@pytest.mark.xfail(reason='BZ-1340718')
def test_pki_server_subsystem_disable_help(ansible_module):
    """
    :id: 256f92da-931f-4384-a002-72c480619fc7
    :Title: Test pki-server subsystem-disable --help command
    :Description: test pki-server subsystem-disable --help command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem 
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults: Verify whether pki-server subsystem-disable --help command shows help option.
    """

    help_out = ansible_module.command('pki-server subsystem-disable --help')
    for result in help_out.values():
        if result['rc'] == 0:
            assert "Usage: pki-server subsystem-disable [OPTIONS] <subsystem ID>" in \
                   result['stdout']
            assert "-i, --instance <instance ID>    Instance ID (default: pki-tomcat)." in \
                   result['stdout']
            assert "-v, --verbose                   Run in verbose mode." in result['stdout']
            assert "--help                      Show help message." in result['stdout']
        else:
            pytest.xfail("Failed to run subsystem --help command.")


def test_pki_server_subsystem_disable_ca(ansible_module):
    """
    :id: 4d4064e9-e1d2-4302-8e66-2c68325aa962
    :Title: Test pki-server subsystem-disable CA Subsystem
    :Description: test pki-server subsystem-disable command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem 
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults: 
        1. Verify whether pki-server subsystem-disable command disables the ca subsystem.
    """
    create_req = 'pki -d {} -c {} -h {} -p {} client-cert-request ' \
                 '"UID=foo1,CN=foo1"'.format(constants.NSSDB, constants.CLIENT_DIR_PASSWORD,
                                             'localhost', constants.CA_HTTP_PORT)
    ca_out = ansible_module.command('pki-server subsystem-disable '
                                    '-i {} ca'.format(constants.CA_INSTANCE_NAME))
    for result in ca_out.values():
        if result['rc'] == 0:
            assert "Subsystem ID: ca" in result['stdout']
            assert "Instance ID: " + constants.CA_INSTANCE_NAME in result['stdout']
            assert "Enabled: False" in result['stdout']
            stat_out = ansible_module.command(create_req)
            for res in stat_out.values():
                if res['rc'] >= 1:
                    assert "PKIException: Not Found" in res['stderr']
        else:
            pytest.xfail("Failed to disable subsystem.")

    ansible_module.command('pki-server subsystem-enable '
                           '-i {} ca'.format(constants.CA_INSTANCE_NAME))


@pytest.mark.parametrize('subsystem', ['kra','ocsp', 'tks', 'tps'])
def test_pki_server_subsystem_disable_other_subsytems(ansible_module, subsystem):
    """
    :id: ff9aaf8b-608c-48d0-ab67-2f271f581f31
    :Title: Test pki-server subsystem-disable KRA,OCSP,TKS,TPS subsystem
    :Description: This test will disable each instance one by one and enable it again.
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server subsystem-disable command disables the kra subsystem.
    """
    instance = eval("constants.{}_INSTANCE_NAME".format(subsystem.upper()))
    cmd_out = ansible_module.command('pki-server subsystem-disable '
                                     '-i {} {}'.format(instance, subsystem))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Subsystem ID: {}".format(subsystem) in result['stdout']
            assert "Instance ID: " + instance in result['stdout']
            assert "Enabled: False" in result['stdout']
        else:
            pytest.xfail("Failed to disable subsystem.")

    ansible_module.command('pki-server subsystem-enable '
                           '-i {} {}'.format(instance, subsystem))


@pytest.mark.skipif("Topology <= 3")
def test_pki_server_subsystem_disable_clone_ca(ansible_module):
    """
    :id: cefc6759-6d79-4242-9ceb-d7928feb8b72
    :Title: Test pki-server subsystem-disable Clone CA subsystem
    :Description: This test will disable the CA subsystem
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server subsystem-disable command disables the clone ca subsystem.
    """
    create_req = 'pki -d {} -c {} -h {} -p {} client-cert-request ' \
                 '"UID=foo1,CN=foo1"'.format(constants.NSSDB, constants.CLIENT_DIR_PASSWORD,
                                             'localhost', constants.CLONECA1_HTTP_PORT)
    ca_out = ansible_module.command('pki-server subsystem-disable '
                                    '-i {} ca'.format(constants.CLONECA1_INSTANCE_NAME))
    for result in ca_out.values():
        if result['rc'] == 0:
            assert "Subsystem ID: ca" in result['stdout']
            assert "Instance ID: " + constants.CLONECA1_INSTANCE_NAME in result['stdout']
            assert "Enabled: False" in result['stdout']
            stat_out = ansible_module.command(create_req)
            for res in stat_out.values():
                if res['rc'] >= 1:
                    assert "Error: CSR generation failed" in res['stdout']
        else:
            pytest.xfail("Failed to disable subsystem.")

    ansible_module.command('pki-server subsystem-enable '
                           '-i {} ca'.format(constants.CA_INSTANCE_NAME))


@pytest.mark.skipif("Topology <= 3")
def test_pki_server_subsystem_disable_sub_ca(ansible_module):
    """
    :id: cefc6759-6d79-4242-9ceb-d7928feb8b72
    :Title: Test pki-server subsystem-disable Sub CA subsystem
    :Description: This test will disable the Sub CA subsystem
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server subsystem-disable command disables the Sub CA subsystem.
    """
    http_port = constants.CA_HTTP_PORT

    create_req = 'pki -d {} -c {} -h {} -p {} client-cert-request ' \
                 '"UID=foo1,CN=foo1"'.format(constants.NSSDB, constants.CLIENT_DIR_PASSWORD,
                                             'localhost', constants.SUBCA1_HTTP_PORT)
    ca_out = ansible_module.command('pki-server subsystem-disable '
                                    '-i {} ca'.format(constants.SUBCA1_INSTANCE_NAME))
    for result in ca_out.values():
        if result['rc'] == 0:
            assert "Subsystem ID: ca" in result['stdout']
            assert "Instance ID: " + constants.SUBCA1_INSTANCE_NAME in result['stdout']
            assert "Enabled: False" in result['stdout']
            stat_out = ansible_module.command(create_req)
            for res in stat_out.values():
                if res['rc'] >= 1:
                    assert "Error: CSR generation failed" in res['stdout']
        else:
            pytest.xfail("Failed to disable subsystem.")

    ansible_module.command('pki-server subsystem-enable '
                           '-i {} ca'.format(constants.SUBCA1_INSTANCE_NAME))


@pytest.mark.skipif("Topology <= 3")
def test_pki_server_subsystem_disable_clone_kra_subsystems(ansible_module):
    """
    :id: 60da7e66-0ea6-4e01-b3ea-584ebc81076c
    :Title: Test pki-server subsystem-disable Clone KRA, subsystem
    :Description: test pki-server subsystem-disable command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server subsystem-disable command disables the clone kra subsystem.
    """
    instance = constants.CLONEKRA1_INSTANCE_NAME
    subsystem = 'kra'
    cmd_out = ansible_module.command('pki-server subsystem-disable '
                                     '-i {} {}'.format(instance, subsystem))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Subsystem ID: kra" in result['stdout']
            assert "Instance ID: " + instance in result['stdout']
            assert "Enabled: False" in result['stdout']
        else:
            pytest.xfail("Failed to disable subsystem.")

    ansible_module.command('pki-server subsystem-enable '
                           '-i {} {}'.format(instance, subsystem))


@pytest.mark.skipif("Topology <= 3")
def test_pki_server_subsystem_disable_clone_ocsp_subsystems(ansible_module):
    """
    :id: feb5dcc6-08bd-43cd-a9fe-fd059df1eb17
    :Title: Test pki-server subsystem-disable Clone OCSP, subsystem
    :Description: test pki-server subsystem-disable command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server subsystem-disable command disables the clone OCSP subsystem.
    """
    instance = constants.CLONEOCSP1_INSTANCE_NAME
    subsystem = 'ocsp'
    cmd_out = ansible_module.command('pki-server subsystem-disable '
                                     '-i {} {}'.format(instance, subsystem))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Subsystem ID: ocsp" in result['stdout']
            assert "Instance ID: " + instance in result['stdout']
            assert "Enabled: False" in result['stdout']
        else:
            pytest.xfail("Failed to disable subsystem.")

    ansible_module.command('pki-server subsystem-enable '
                           '-i {} {}'.format(instance, subsystem))


@pytest.mark.skipif("Topology <= 3")
def test_pki_server_subsystem_disable_clone_tks_subsystems(ansible_module):
    """
    :id: 5bce91ac-e076-451f-98bb-15e5e407e6cb
    :Title: Test pki-server subsystem-disable Clone TKS, subsystem
    :Description: test pki-server subsystem-disable command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server subsystem-disable command disables the clone TKS subsystem.
    """
    instance = constants.CLONETKS1_INSTANCE_NAME
    subsystem = 'tks'
    cmd_out = ansible_module.command('pki-server subsystem-disable '
                                     '-i {} {}'.format(instance, subsystem))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Subsystem ID: tks" in result['stdout']
            assert "Instance ID: " + instance in result['stdout']
            assert "Enabled: False" in result['stdout']
        else:
            pytest.xfail("Failed to disable subsystem.")

    ansible_module.command('pki-server subsystem-enable '
                           '-i {} {}'.format(instance, subsystem))


def test_pki_server_subsystem_disable_invald_instance(ansible_module):
    """
    :id: f4677d13-1af9-48cd-955d-e690bce2e9ac
    :Title: Test pki-server subsystem-disable with invalid instance.
    :Description: test pki-server subsystem-disable command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem 
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults: 
        1. Verify whether pki-server subsystem-disable command throws error when non existing 
        instance name is supplied.
    """
    junk_instance = ''.join(random.choice(string.ascii_uppercase + string.digits)
                            for _ in range(10))
    ca_out = ansible_module.command('pki-server subsystem-disable -i {} ca'.format(junk_instance))
    for result in ca_out.values():
        if result['rc'] >= 1:
            assert "ERROR: Invalid instance " + junk_instance in result['stdout']
        else:
            pytest.xfail("Failed: Disabled the Invalid subsystem")


@pytest.mark.xfail(reason='BZ=1356588')
def test_pki_server_subsystem_disable_invald_subsystemType(ansible_module):
    """
    :id: 896ffd77-718d-4100-9210-19c457191c4f
    :Title: Test pki-server subsystem-disable with invalid subsystem.
    :Description: test pki-server subsystem-disable command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :ExpectedResults: 
        1.Verify whether pki-server subsystem-disable command throws error when non existing 
        instance type is supplied.
    """
    junk_subsystemType = ''.join(random.choice(string.ascii_uppercase + string.digits)
                                 for _ in range(10))
    ca_out = ansible_module.command('pki-server subsystem-disable '
                                    '-i {} {}'.format(constants.CA_INSTANCE_NAME,
                                                      junk_subsystemType))
    for result in ca_out.values():
        if result['rc'] >= 1:
            assert "ERROR: No %s subsystem in instance %s." % (junk_subsystemType,
                                                               constants.CA_INSTANCE_NAME) in \
                   result['stdout']
        else:
            pytest.xfail("Failed: Disabled the subsystem with invalid subsystem type")


@pytest.mark.xfail(reason='BZ=1356588')
def test_pki_server_subsystem_disable_disabled_subsystem(ansible_module):
    """
    :id: c272cc50-4bd1-417e-8e29-65b87e087b8e
    :Title: Test pki-server subsystem-disable cli with disabled subsystem.
    :Description: test pki-server subsystem-disable command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server subsystem-disable command throws error when trying to disable
        the disabled subsystem.
    """
    ansible_module.command('pki-server subsystem-disable '
                           '-i {} ca'.format(constants.CA_INSTANCE_NAME))
    ca_out = ansible_module.command('pki-server subsystem-disable '
                                    '-i {} ca'.format(constants.CA_INSTANCE_NAME))
    for result in ca_out.values():
        if result['rc'] == 0:
            assert 'Subsystem "ca" is already disabled' in result['stdout']
            assert "Subsystem ID: ca" in result['stdout']
            assert "Instance ID: " + constants.CA_INSTANCE_NAME in result['stdout']
            assert "Enabled: False" in result['stdout']
        else:
            pytest.xfail("Failed: Disabled the already disabled subsystem")
    ansible_module.command('pki-server subsystem-enable '
                           '-i {} ca'.format(constants.CA_INSTANCE_NAME))
