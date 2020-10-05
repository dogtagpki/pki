"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki-server subsystem cli commands needs to be tested:
#   pki-server subsystem
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
from pki.testlib.common import utils

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants
TOPOLOGY = constants.CA_INSTANCE_NAME.split("-")[-2]
log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)


def test_pki_server_subsystem(ansible_module):
    """
    :id: 990d3ac6-b879-47cb-a4e7-ddd62c80562b
    :Title: Test pki-server subsystem command
    :Description: test pki-server subsystem command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem 
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server subsystem command shows subsystem-disable,subsystem-enable,
           subsystem-find, subsystem-show, subsystem-cert commands
    """
    sub_out = ansible_module.command('pki-server subsystem')
    for result in sub_out.values():
        if result['rc'] == 0:
            assert "subsystem-disable             Disable subsystem" in result['stdout']
            assert "subsystem-enable              Enable subsystem" in result['stdout']
            assert "subsystem-find                Find subsystems" in result['stdout']
            assert "subsystem-show                Show subsystem" in result['stdout']
            assert "subsystem-cert                Subsystem certificate management commands" in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()


def test_pki_server_subsystem_junk(ansible_module):
    """
    :id: 990d3ac6-b879-47cb-a4e7-ddd62c80562b
    :Title: Test pki-server subsystem with junk sub command.
    :Description: test pki-server subsystem command
    :CaseComponent: \-
    :Requirement: Pki Server Subsystem
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults: Verify whether pki-server subsystem command throws error with junk option.
    """
    junk = utils.get_random_string(len=10)
    junk_exception = 'ERROR: Invalid module "%s"' % junk
    subsystem_junk_output = ansible_module.command('pki-server subsystem {}'.format(junk))
    for result in subsystem_junk_output.values():
        if result['rc'] >= 1:
            assert junk_exception in result['stderr']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()
