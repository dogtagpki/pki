#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI CA-USER-CERT CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki user commands needs to be tested:
#   pki ca-user-cert
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

import pytest
import sys
import re

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)


@pytest.mark.parametrize('args', ['--help', '', 'asdfa'])
def test_pki_ca_user_cert_help_command(ansible_module, args):
    """
    :Title: Test pki ca-user-cert --help command
    :Description: Command should show pki ca-user-cert --help options and uses.
    :Requirement:  Certificate Authority Users
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    """

    user_cert = 'pki ca-user-cert {}'.format(args)
    cmd_out = ansible_module.command(user_cert)
    for result in cmd_out.values():
        if args == '--help' or args == '':
            assert "Commands:" in result['stdout']
            assert re.search("ca-user-cert-find\s+Find user certificates", result['stdout'])
            assert re.search("ca-user-cert-show\s+Show user certificate", result['stdout'])
            assert re.search("ca-user-cert-add\s+Add user certificate",result['stdout'])
            assert re.search("ca-user-cert-del\s+Remove user certificate", result['stdout'])
            log.info('Successfully ran: {}'.format(result['cmd']))
        elif args == 'asdfa':
            assert 'Invalid module "ca-user-cert-{}"'.format(args) in result['stderr']
        else:
            log.error('Failed to run: {}'.format(result['cmd']))
            pytest.xfail()

