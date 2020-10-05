"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki-server subsystem cli commands needs to be tested:
#   pki-server susbsystem-show
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

from pki.testlib.common.utils import UserOperations, get_random_string

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
def test_pki_server_subsystem_show_help(ansible_module):
    """
    :id: 120b145a-4fbd-4751-88f5-3d7f76ebbe5b
    :Title: Test pki-server subsystem-show --help command 
    :Description: test pki-server subsystem-show --help command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults: 
        1. Verify whether pki-server subsystem-show --help command shows help options.
    """
    find_out = ansible_module.command('pki-server subsystem-show --help')
    for result in find_out.values():
        if result['rc'] == 0:
            assert "Usage: pki-server subsystem-show [OPTIONS] <subsystem ID>" in \
                   result['stdout']
            assert "-i, --instance <instance ID>    Instance ID (default: pki-tomcat)." in \
                   result['stdout']
            assert "-v, --verbose                   Run in verbose mod" in result['stdout']
            assert "--help                      Show help message." in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()


def test_pki_server_subsystem_show_ca(ansible_module):
    """
    :id: ea11ea09-ce9c-49fd-906d-f7fe375392b1
    :Title: Test pki-server subsystem-show CA subsystem 
    :Description: test pki-server subsystem-show command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults: 
        1. Verify whether pki-server subsystem-show command shows ca subsystem info.
    """
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
    else:
        instance = constants.CA_INSTANCE_NAME
    ansible_module.command('pki-server subsystem-enable -i {} ca'.format(instance))
    find_ca_out = ansible_module.command('pki-server subsystem-show -i {} ca'.format(instance))
    for result in find_ca_out.values():
        if result['rc'] == 0:
            assert "Subsystem ID: ca" in result['stdout']
            assert "Instance ID: " + instance in result['stdout']
            assert "Enabled: True" in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()


def test_pki_server_subsystem_show_kra(ansible_module):
    """
    :id: 70cfd06f-fbb9-4168-bec6-8a2c90dc7e16
    :Title: Test pki-server subsystem-show KRA subsystem
    :Description: test pki-server subsystem-show command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults: 
        1. Verify whether pki-server subsystem-show command shows the kra subsystem info.
    """
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
    else:
        instance = constants.KRA_INSTANCE_NAME
    ansible_module.command('pki-server subsystem-enable -i {} kra'.format(instance))
    kra_out = ansible_module.command('pki-server subsystem-show -i {} kra'.format(instance))
    for result in kra_out.values():
        if result['rc'] == 0:
            assert "Subsystem ID: kra" in result['stdout']
            assert "Instance ID: " + instance in result['stdout']
            assert "Enabled: True" in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()



def test_pki_server_subsystem_show_ocsp(ansible_module):
    """
    :id: d9439026-75e6-4f38-a9b8-0ef14ee85da0
    :Title: Test pki-server subsystem-show OCSP subsystem
    :Description: test pki-server subsystem-show command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults: 
        1. Verify whether pki-server subsystem-show command shows the ocsp subsystem info.
    """
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
    else:
        instance = constants.OCSP_INSTANCE_NAME
    ansible_module.command('pki-server subsystem-enable -i {} ocsp'.format(instance))
    ocsp_out = ansible_module.command('pki-server subsystem-show -i {} ocsp'.format(instance))
    for result in ocsp_out.values():
        if result['rc'] == 0:
            assert "Subsystem ID: ocsp" in result['stdout']
            assert "Instance ID: " + instance in result['stdout']
            assert "Enabled: True" in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()


def test_pki_server_subsystem_show_tks(ansible_module):
    """
    :id: c9513c73-68a7-4d1a-8c6c-c431c426b723
    :Title: Test pki-server subsystem-show TKS Subsystem
    :Description: test pki-server subsystem-show command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults: 
        1. Verify whether pki-server subsystem-show command shows the tks subsystem info.
    """
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
    else:
        instance = constants.TKS_INSTANCE_NAME
    ansible_module.command('pki-server subsystem-enable -i {} tks'.format(instance))
    tks_out = ansible_module.command('pki-server subsystem-show -i {} tks'.format(instance))
    for result in tks_out.values():
        if result['rc'] == 0:
            assert "Subsystem ID: tks" in result['stdout']
            assert "Instance ID: " + instance in result['stdout']
            assert "Enabled: True" in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()


def test_pki_server_subsystem_show_tps(ansible_module):
    """
    :id: 4383e7a2-1367-42d3-a163-b6d7667c9d0f
    :Title: Test pki-server subsystem-show TPS subsystem
    :Description: test pki-server subsystem-show command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults: 
        1. Verify whether pki-server subsystem-show command shows the tps subsystem info.
    """
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
    else:
        instance = constants.TPS_INSTANCE_NAME
    ansible_module.command('pki-server subsystem-enable -i {} tps'.format(instance))
    tps_out = ansible_module.command('pki-server subsystem-show -i {} tps'.format(instance))
    for result in tps_out.values():
        if result['rc'] == 0:
            assert "Subsystem ID: tps" in result['stdout']
            assert "Instance ID: " + instance in result['stdout']
            assert "Enabled: True" in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()


@pytest.mark.skipif("TOPOLOGY <= 3")
def test_pki_server_subsystem_show_ca_clone(ansible_module):
    """
    :id: 8559f050-4ddb-4a53-8d5a-f5d1129bb234
    :Title: Test pki-server subsystem-show CA Clone subsystem
    :Description: test pki-server subsystem-show command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults: 
        1. Verify whether pki-server subsystem-show command shows ca clone subsystem info.
    """
    ansible_module.command('pki-server subsystem-enable -i {} ca'.format(constants.CLONECA1_INSTANCE_NAME))
    clone_ca_out = ansible_module.command('pki-server subsystem-show -i {} ca'.format(constants.CLONECA1_INSTANCE_NAME))
    for result in clone_ca_out.values():
        if result['rc'] == 0:
            assert "Subsystem ID: ca" in result['stdout']
            assert "Instance ID: " + constants.CLONECA1_INSTANCE_NAME in result['stdout']
            assert "Enabled: True" in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()


@pytest.mark.skipif("TOPOLOGY <= 3")
def test_pki_server_subsystem_show_kra_clone(ansible_module):
    """
    :id: 476b35d1-283c-41be-addf-3b87f89d017f
    :Title: Test pki-server subsystem-show KRA Clone subsystem
    :Description: test pki-server subsystem-show command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server subsystem-show command shows the kra clone subsystem info.
    """
    ansible_module.command('pki-server subsystem-enable -i {} '
                           'kra'.format(constants.CLONEKRA1_INSTANCE_NAME))
    clone_kra_out = ansible_module.command('pki-server subsystem-show '
                                           '-i {} kra'.format(constants.CLONEKRA1_INSTANCE_NAME))
    for result in clone_kra_out.values():
        if result['rc'] == 0:
            assert "Subsystem ID: kra" in result['stdout']
            assert "Instance ID: " + constants.CLONEKRA1_INSTANCE_NAME in result['stdout']
            assert "Enabled: True" in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()


@pytest.mark.skipif("TOPOLOGY <= 3")
def test_pki_server_subsystem_show_ocsp_clone(ansible_module):
    """
    :id: 2331fecb-88fe-497d-9bfb-3f0ee26fb812
    :Title: Test pki-server subsystem-show OCSP Clone subsystem
    :Description: test pki-server subsystem-show command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults: 
        1. Verify whether pki-server subsystem-show command shows the ocsp clone subsystem info.
    """
    ansible_module.command('pki-server subsystem-enable -i {} '
                           'ocsp'.format(constants.CLONEOCSP1_INSTANCE_NAME))
    ocsp_output = ansible_module.command(
        'pki-server subsystem-show -i {} ocsp'.format(constants.CLONEOCSP1_INSTANCE_NAME))
    for result in ocsp_output.values():
        if result['rc'] == 0:
            assert "Subsystem ID: ocsp" in result['stdout']
            assert "Instance ID: " + constants.CLONEOCSP1_INSTANCE_NAME in result['stdout']
            assert "Enabled: True" in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()


@pytest.mark.skipif("TOPOLOGY <= 3")
def test_pki_server_subsystem_show_tks_clone(ansible_module):
    """
    :id: e015d890-3b13-449b-8726-01f1103a9c52
    :Title: Test pki-server subsystem-show TKS Clone subsystem
    :Description: test pki-server subsystem-show command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults: 
        1. Verify whether pki-server subsystem-show command shows the tks clone subsystem info.
    """
    ansible_module.command('pki-server subsystem-enable -i {} '
                           'tks'.format(constants.CLONETKS1_INSTANCE_NAME))
    tks_out = ansible_module.command(
        'pki-server subsystem-show -i {} tks'.format(constants.CLONETKS1_INSTANCE_NAME))
    for result in tks_out.values():
        if result['rc'] == 0:
            assert "Subsystem ID: tks" in result['stdout']
            assert "Instance ID: " + constants.CLONETKS1_INSTANCE_NAME in result['stdout']
            assert "Enabled: True" in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()


@pytest.mark.skipif("TOPOLOGY <= 3")
def test_pki_server_subsystem_show_subca(ansible_module):
    """
    :id: 723434f4-297b-4f8c-9d68-1e26ba2a9ca1
    :Title: Test pki-server subsystem-show Sub CA subsystem
    :Description: test pki-server subsystem-show command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server subsystem-show command shows the subca subsystem info.
    """
    ansible_module.command('pki-server subsystem-enable -i {} '
                           'ca'.format(constants.SUBCA1_INSTANCE_NAME))
    tks_output = ansible_module.command(
        'pki-server subsystem-show -i {} ca'.format(constants.SUBCA1_INSTANCE_NAME))
    for result in tks_output.values():
        if result['rc'] == 0:
            assert "Subsystem ID: ca" in result['stdout']
            assert "Instance ID: " + constants.SUBCA1_INSTANCE_NAME in result['stdout']
            assert "Enabled: True" in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()


@pytest.mark.skipif("TOPOLOGY <= 3")
def test_pki_server_subsystem_show_invalid_instance(ansible_module):
    """
    :id: 7febdbae-0b25-496e-bcbe-aa9b56233c14
    :Title: Test pki-server subsystem-show invalid instance
    :Description: test pki-server subsystem-show command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server subsystem-show command throws error when ran with the
        non-existing instance name.
    """
    junk_instance = get_random_string()
    subsystem_show_output = ansible_module.command('pki-server subsystem-show '
                                                   '-i {} ca'.format(junk_instance))
    for result in subsystem_show_output.values():
        if result['rc'] >= 1:
            assert "ERROR: Invalid instance " + junk_instance in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()


# @pytest.mark.xfail(reason='BZ=1356918')
def test_pki_server_subsystem_show_invalid_subsystemType(ansible_module):
    """
    :id: c0730d09-9f78-4988-9dd5-8011bca12825
    :Title: Test pki-server subsystem-show invalid subsystem type
    :Description: test pki-server subsystem-show command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem 
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults: 
        1. Verify whether pki-server subsystem-show command throws error when ran with the 
        invalid subsystem type.
    """
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
    else:
        instance = constants.CA_INSTANCE_NAME
    junk_subsystemType = get_random_string()
    subsystem_show_output = ansible_module.command('pki-server subsystem-show -i {} {}'.format(instance,
                                                                                               junk_subsystemType))
    for result in subsystem_show_output.values():
        if result['rc'] >= 1:
            assert "ERROR: No {} subsystem in instance {}.".format(junk_subsystemType,
                                                                   instance) in result['stderr']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()
