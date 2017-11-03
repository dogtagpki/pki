"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI TPS-TOKEN-SHOW tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki tps commands needs to be tested:
#   pki tps-token-show
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Geetika Kapoor <gkapoor@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2016 Red Hat, Inc. All rights reserved.
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
"""


import pytest
import ansible
import logging
from ansible.inventory import Inventory
from pytest_ansible import plugin
import ansible.constants
import os

from test_steps import *
import random

@pytest.mark.ansible_playbook_setup('ldapUserAdd.yml', 'tokenEnroll.yml')
@pytest.mark.setup
def test_setup(ansible_playbook):
    pass

@pytest.mark.parametrize("certnick,expected", [
    ('PKI TPS Administrator for Example.Org', ['Token ID: 40906145C76224192D2B', 'User ID: foobar', 'Type: userKey', 'Status: ACTIVE']),
])

@pytest.mark.positive
def test_tpstoken_show_validgroup(ansible_module, certnick, expected):
    """
    :Test: test tps-token command

    :Title: RHCS-TC test tps-token-show command for groups that
                can see token information.

    :Description: Command should successfully show tokens.

    :Requirement: RHCS-REQ TPS Server CLI Tests

    :Setup: Use the subsystems setup in ansible to run subsystem commands

    :Assert: Verify whether tps-token-show should display tokens

    :CaseComponent: -
    """
    contacted = ansible_module.pki(
        cli='tps-token-show',
        extra_args='40906145C76224192D2B',
        protocol='http',
        certnick=certnick
        )
    for (host, result) in contacted.items():
        for iter in expected:
            ok("Certificate: %s, Expected Output: %s , Actual Output : %s" %(certnick, iter, result['stdout']))
            assert iter in result['stdout']
@pytest.mark.parametrize("certnick,expected", [
    ("PKI TPS Administrator for Example.Org", ["PKIException: Record not found"]),
])

@pytest.mark.negative
def test_tpstoken_show_exception(ansible_module, certnick, expected):
    """
    :Test: test tps-token command

    :Title: RHCS-TC test tps-token-show command when token
            doesn't exist in the records.
    :Description: Command should give "Records" not found.

    :Requirement: RHCS-REQ TPS Server CLI Tests

    :Setup: Use the subsystems setup in ansible to run subsystem commands

    :Assert: Verify that no records message is populated.

    :CaseComponent: -
    """
    contacted = ansible_module.pki(
        cli='tps-token-show',
        extra_args='40906145C76224192D2BRR',
        certnick=certnick
        )
    for (host, result) in  contacted.items():
        for iter in expected:
            ok("Certificate: %s, Expected Output: %s , Actual Output : %s" %(certnick, iter, result['stderr']))
            assert iter in result['stderr']

@pytest.mark.positive
@pytest.mark.parametrize("extra_args, certnick, expected", [
    ('40906145C76224192D2B', 'PKI TPS Administrator for Example.Org', ['Token ID: 40906145C76224192D2B', 'User ID: foobar', 'Type: userKey', 'Status: ACTIVE']),
    ('--help', 'PKI TPS Administrator for Example.Org', ['usage: tps-token-show', '<Token ID>', '--help   Show help options']),
])

@pytest.mark.positive
def test_tpstoken_show_help(ansible_module, extra_args, certnick, expected):
    """
    :Test: test tps-token command

    :Title: RHCS-TC test tps-token-show command for groups that
            can see token information using http secure connect.

    :Description: Command should successfully show tokens.

    :Requirement: RHCS-REQ TPS Server CLI Tests

    :Setup: Use the subsystems setup in ansible to run subsystem commands

    :Assert: Verify whether tps-token-show should display tokens

    :CaseComponent: -
    """
    contacted = ansible_module.pki(
        cli='tps-token-show',
        extra_args=extra_args,
        protocol='https',
        certnick=certnick
        )
    for (host, result) in  contacted.items():
        for iter in expected:
            ok("Certificate: %s, Expected Output: %s , Actual Output : %s" %(certnick, iter, result['stdout']))
            assert iter in result['stdout']
