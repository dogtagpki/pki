"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI-SERVER CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki securitydomain commands needs to be tested:
#   pki-server instance 
#   pki-server instance --help
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

import pytest


def test_pki_server_instance_command(ansible_module):
    """
    :id: f86ab34f-1d77-465d-9c61-f7bc65b03e84
    :Title: Test pki-server instance --help command
    :Description:
        test pki-server instance --help command
        This test also verifies bugzilla id : 1339263
    :CaseComponent: \-
    :Requirement: Pki Server Instance
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        Verify whether pki-server instance --help command shows the following commands.

        Commands:
         instance-cert                 Instance certificate management commands
         instance-find                 Find instances
         instance-show                 Show instance
         instance-start                Start instance
         instance-stop                 Stop instance
         instance-migrate              Migrate instance
         instance-nuxwdog-enable       Instance enable nuxwdog
         instance-nuxwdog-disable      Instance disable nuxwdog
         instance-externalcert-add     Add external certificate or chain to the instance
         instance-externalcert-del     Delete external certificate from the instance

    """
    cmd_output = ansible_module.command('pki-server instance --help')
    for result in cmd_output.values():
        if result['rc'] == 0:
            assert "Commands:" in result['stdout']
            assert "instance-cert                 Instance certificate management commands" in \
                   result['stdout']
            assert "instance-find                 Find instances" in result['stdout']
            assert "instance-show                 Show instance" in result['stdout']
            assert "instance-start                Start instance" in result['stdout']
            assert "instance-stop                 Stop instance" in result['stdout']
            assert "instance-migrate              Migrate instance" in result['stdout']
            assert "instance-nuxwdog-enable       Instance enable nuxwdog" in result['stdout']
            assert "instance-nuxwdog-disable      Instance disable nuxwdog" in result['stdout']
            assert "instance-externalcert-add     Add external certificate or chain to the " \
                   "instance" in result['stdout']
            assert "instance-externalcert-del     Delete external certificate from the " \
                   "instance" in result['stdout']
        else:
            pytest.skip("Failed to run pki-server instance --help command")
