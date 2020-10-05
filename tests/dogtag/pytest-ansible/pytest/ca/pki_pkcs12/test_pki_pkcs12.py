"""
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 #
 #   Description: Tests for pki pkcs12 CLI
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


@pytest.mark.parametrize('options', ('--help', 'ofeowjf', ''))
def test_pki_pkcs12(ansible_module, options):
    """
    :id: b1232392-04d1-4b01-810e-14b3568edc05
    :Title: Test pki pkcs12 command, to show it's sub commands.
    :Requirement: Pki Pkcs12
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps: Run pki pkcs12 with '' '--help and ofeowjf values.
    :ExpectedResults:
        1. It will show child commands with ''
        2. It will show child commands with --help
        3. It will throw an error.
    """

    pki_pkcs12_output = ansible_module.command('pki pkcs12 {}'.format(options))
    for result in pki_pkcs12_output.values():
        if result['rc'] == 0:
            assert "pkcs12-cert" in result['stdout']
            assert "pkcs12-export" in result['stdout']
            assert "pkcs12-import" in result['stdout']
            assert "pkcs12-key" in result['stdout']
        elif result['rc'] >= 1:
            if options in result['stderr']:
                assert 'ERROR: Invalid module "pkcs12-{}".'.format(options) in result['stderr']
            else:
                pytest.fail()
