"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki-server subsystem cli commands needs to be tested:
#   pki-server subsystem-find
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
def test_pki_server_subsystem_find_help(ansible_module):
    """
    :id: 35f3979a-0dea-4c15-97b1-579e378fea20
    :Title: Test pki-server subsystem-find --help command
    :Description: test pki-server subsystem-find --help command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults: Verify whether pki-server subsystem-find --help shows help options.
    """
    find_out = ansible_module.command('pki-server subsystem-find --help')
    for result in find_out.values():
        if result['rc'] == 0:
            assert "Usage: pki-server subsystem-find [OPTIONS]" in \
                   result['stdout']
            assert "-i, --instance <instance ID>    Instance ID (default: pki-tomcat)." in \
                   result['stdout']
            assert "-v, --verbose                   Run in verbose mod" in result['stdout']
            assert "--help                      Show help message." in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()


@pytest.mark.skipif("TOPOLOGY != 1")
def test_pki_server_subsystem_find_shared_tomcat(ansible_module):
    """
    :id: 3ecea9f3-536b-4c4c-bc66-a7f67058a9a4
    :Title: Test pki-server subsystem-find shared tomcat instance
    :Description: test pki-server subsystem-find command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
            It assumes that all the subsystem ca, kra, ocsp, tks and tps installed
            with shared tomcat instance.
    :Steps:
    :ExpectedResults: Verify whether pki-server subsystem-find command list the subsystem.
    """
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
        kra_instance = ocsp_instance = tks_instance = tps_instance = instance
    else:
        instance = constants.CA_INSTANCE_NAME
        kra_instance = constants.KRA_INSTANCE_NAME
        ocsp_instance = constants.OCSP_INSTANCE_NAME
        tks_instance = constants.TKS_INSTANCE_NAME
        tps_instance = constants.TPS_INSTANCE_NAME

    find_out = ansible_module.command('pki-server subsystem-find -i {}'.format(instance))
    for result in find_out.values():
        if result['rc'] == 0:
            assert "entries matched" in result['stdout']
            assert "Subsystem ID: ca" in result['stdout']
            assert "Instance ID: " + instance in result['stdout']
            assert "Enabled: True" in result['stdout']
            assert "Subsystem ID: kra" in result['stdout']
            assert "Instance ID: " + kra_instance in result['stdout']
            assert "Enabled: True" in result['stdout']
            assert "Subsystem ID: ocsp" in result['stdout']
            assert "Instance ID: " + ocsp_instance in result['stdout']
            assert "Enabled: True" in result['stdout']
            assert "Subsystem ID: tks" in result['stdout']
            assert "Instance ID: " + tks_instance in result['stdout']
            assert "Enabled: True" in result['stdout']
            assert "Subsystem ID: tps" in result['stdout']
            assert "Instance ID: " + tps_instance in result['stdout']
            assert "Enabled: True" in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()


@pytest.mark.parametrize('subsystem', ['ca', 'kra'])  # TODO remove after build, 'ocsp', 'tks', 'tps'])
def test_pki_server_subsystem_find_discrete_tomcat_ca(ansible_module, subsystem):
    """
    :id: 9994fa93-cd02-4d42-a19a-1d952fe9a186
    :Title: Test pki-server subsystem-find discrete tomcat CA instances
    :Description: test pki-server subsystem-find command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem command, It will setup
            topology-02 which have all discrete tomcat instances.

    :ExpectedResults: Verify whether pki-server subsystem-find command list the subsystem.
    """
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
    else:
        instance = eval("constants.{}_INSTANCE_NAME".format(subsystem.upper()))
    ansible_module.command('pki-server subsystem-enable -i {} {}'.format(instance, subsystem))
    find_output = ansible_module.command('pki-server subsystem-find -i {}'.format(instance))
    for result in find_output.values():
        if result['rc'] == 0:
            assert "entries matched" in result['stdout']
            assert "Subsystem ID: {}".format(subsystem) in result['stdout']
            assert "Instance ID: " + instance in result['stdout']
            assert "Enabled: " in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()


@pytest.mark.skipif("TOPOLOGY <= 3")
def test_pki_server_subsystem_find_clone_subsystems(ansible_module):
    """
    :id: 20305fe7-3dff-444f-a437-00ac7ddd386a
    :Title: Test pki-server subsystem-find clone CA instance
    :Description: test pki-server subsystem-find command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem command
    :Steps:
    :ExpectedResults: 
        1. Verify whether pki-server subsystem-find command list the clone ca subsystem info.
    """
    subsystems = [['ca', constants.CLONECA1_INSTANCE_NAME],
                  ['kra', constants.CLONEKRA1_INSTANCE_NAME],
                  ['ocsp', constants.CLONEOCSP1_INSTANCE_NAME],
                  ['tks', constants.CLONETKS1_INSTANCE_NAME],
                  ['tps', constants.CLONETKS1_INSTANCE_NAME]]
    for subsystem, instance in subsystems:
        find_out = ansible_module.command('pki-server subsystem-find -i {}'.format(instance))
        for result in find_out.values():
            if result['rc'] == 0:
                assert "entries matched" in result['stdout']
                assert "Subsystem ID: {}".format(subsystem) in result['stdout']
                assert "Instance ID: " + instance in result['stdout']
                assert "Enabled: True" in result['stdout']
                log.info("Successfully run : {}".format(" ".join(result['cmd'])))
            else:
                log.error("Failed to run : {}".format(" ".join(result['cmd'])))
                pytest.skip()


@pytest.mark.skipif("TOPOLOGY <= 3")
def test_pki_server_subsystem_find_subca(ansible_module):
    """
    :id: 97efc8b2-7012-4d2d-8a49-866fcd6d19fd
    :Title: Test pki-server subsystem-find Sub CA instance
    :Description: test pki-server subsystem-find command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem command
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server subsystem-find command list the subca subsystem
    info.
    """
    find_out = ansible_module.command('pki-server subsystem-find '
                                      '-i {}'.format(constants.SUBCA1_INSTANCE_NAME))
    for result in find_out.values():
        if result['rc'] == 0:
            assert "entries matched" in result['stdout']
            assert "Subsystem ID: ca" in result['stdout']
            assert "Instance ID: " + constants.SUBCA1_INSTANCE_NAME in result['stdout']
            assert "Enabled: True" in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()


def test_pki_server_subsystem_find_junk(ansible_module):
    """
    :id: 474d4d9a-6fcd-4522-9aae-6f945c520670
    :Title: Test pki-server subsystem-find invalid instance
    :Description: test pki-server subsystem-find command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults: Verify whether pki-server subsystem-find command list no subsystem.
    """
    junk = get_random_string(len=40)
    junk_out = ansible_module.command('pki-server subsystem-find -i {}'.format(junk))
    for result in junk_out.values():
        if result['rc'] >= 1:
            assert "ERROR: Invalid instance %s" % junk in result['stderr']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()
