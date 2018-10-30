"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   Description: PKI CLIENT CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki client cli commands needs to be tested:
#   pki client
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Amol Kahat <akaht@redhat.com>
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
import sys

import pytest

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)


@pytest.mark.parametrize('args', ['--help', '', 'asfd'])
def test_pki_client_help(ansible_module, args):
    """
    :Title: Test pki client --help command
    :Description: Test pki client command, with different options.
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Requirement: Pki Client
    :Steps:
        1. pki client --help
        2. pki client
        3. pki client asfd
    :Expectedresults:
        1. It should show client subcommands.
        2. It should show client subcommands.
        3. It should show invalid module error with 'asfd'
    """
    help_out = ansible_module.command('pki client {}'.format(args))
    for result in help_out.values():
        if result['rc'] == 0:
            assert "client-init             Initialize client security database" in \
                   result['stdout']
            assert "client-cert-find        Find certificates in client security database" in \
                   result['stdout']
            assert "client-cert-import      Import certificate into client security database" in \
                   result['stdout']
            assert "client-cert-mod         Modify certificate in client security database" in \
                   result['stdout']
            assert "client-cert-del         Remove certificate from client security database" in \
                   result['stdout']
            assert "client-cert-request     Request a certificate" in result['stdout']
            assert "client-cert-show        Show certificate in client security database" in \
                   result['stdout']
            assert "client-cert-validate    Validate certificate" in result['stdout']
            log.info("Successfully run pki client command.")
        else:
            assert 'Error: Invalid module "client-{}"'.format(args) in result['stderr']
            log.info("Successfully ran the pki client command.")
