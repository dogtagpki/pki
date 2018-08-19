#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Automation for tps-activity-show CLI
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Sumedh Sidhaye <ssidhaye@redhat.com>
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
import sys
import re
import pytest

from pki.testlib.common.certlib import *

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

ACTIVITY_IDS = []

@pytest.mark.setup
def test_setup(ansible_module):
    """pre-requisites for running the test"""
    activity_find_output = ansible_module.pki(
        cli='tps-activity-find',
        nssdb=constants.NSSDB,
        port=constants.TPS_HTTP_PORT,
        protocol='http',
        certnick='TPS_AdminV',
    )
    for result in activity_find_output.values():
        global ACTIVITY_IDS
        ACTIVITY_IDS = re.findall("Activity ID\: [0-9]+\.[0-9]+", result['stdout'])
        ACTIVITY_IDS = [item.split(':')[1].strip() for item in ACTIVITY_IDS]


def test_tpsactivity_show_validnicks(ansible_module):
    """
    :Title: Run tps-activity-show with valid certnicks

    :Description: Run tps-activity-show with valid certnicks

    :Requirement: TPS Server CLI Tests

    :Setup:
        Use subsystems setup via ansible playbooks

    :Steps:
        Setup Dogtagpki using ansible playbooks

    :Expectedresults:
        Dogtagpki should be setup via ansible playbooks

    :Automated: Yes

    :CaseComponent: \-
    """
    global ACTIVITY_IDS
    certnicks = ['TPS_AdminV', 'TPS_AgentV', 'TPS_OperatorV']
    for activity_id, certnick in zip(ACTIVITY_IDS, certnicks):
        activity_show_output = ansible_module.pki(
            cli='tps-activity-show',
            nssdb=constants.NSSDB,
            port=constants.TPS_HTTP_PORT,
            protocol='http',
            certnick=certnick,
            extra_args=activity_id
        )
        for result in activity_show_output.values():
            assert "Activity ID: %s" % activity_id in result['stdout']
            if "Operation: format" in result['stdout']:
                assert "Token ID: %s" % constants.CUID in result['stdout']
                assert "User ID: jdoe" in result['stdout']
                assert "Result: success" in result['stdout']
                assert "Message: token format operation" in result['stdout']
            if "Operation: add" in result['stdout']:
                assert "Token ID: %s" % constants.CUID in result['stdout']
                assert "User ID: jdoe" in result['stdout']
                assert "Result: success" in result['stdout']
                assert "Message: add token during format" in result['stdout']
            if "Operation: pin_reset" in result['stdout']:
                assert "Token ID: %s" % constants.CUID in result['stdout']
                assert "User ID: jdoe" in result['stdout']
                assert "Result: success" in result['stdout']
                assert "Message: update token during pin reset" in result['stdout']
            if "Operation: enrollment" in result['stdout']:
                pattern = re.compile(r'(Message: appletVersion=\d{3}; tokenType =userKey; userid =[a-zA-z0-9]*)')
                if pattern.findall(result['stdout']):
                    result['stdout'].find(r'(Message: appletVersion=\d{3}; tokenType =userKey; userid =[a-zA-z0-9]*)')
                assert "Token ID: %s" % constants.CUID in result['stdout']
                assert "User ID: jdoe" in result['stdout']
                assert "Result: success" in result['stdout']

@pytest.mark.parametrize("certnick,expected", [
    ("TPS_AdminR", ["FATAL: SSL alert received: CERTIFICATE_REVOKED"]),
    ("TPS_AdminE", ["FATAL: SSL alert received: CERTIFICATE_EXPIRED"]),
    ("TPS_AgentR", ["FATAL: SSL alert received: CERTIFICATE_REVOKED"]),
    ("TPS_AgentE", ["FATAL: SSL alert received: CERTIFICATE_EXPIRED"]),
    ("TPS_OperatorR", ["FATAL: SSL alert received: CERTIFICATE_REVOKED"]),
    ("TPS_OperatorE", ["FATAL: SSL alert received: CERTIFICATE_EXPIRED"]),
])
def test_tpsactivityshow_invalidnicks(ansible_module, certnick, expected):
    """
    :Title: Run tps-activity-show with expired and revoked certnicks

    :Description: Run tps-activity-show with expired and revoked certnicks

    :Requirement: TPS Server CLI Tests

    :Setup:
        Use subsystems setup via ansible playbooks

    :Steps:
        Setup Dogtagpki using ansible playbooks

    :Expectedresults:
        Dogtagpki should be setup via ansible playbooks

    :Automated: Yes

    :CaseComponent: \-
    """
    global ACTIVITY_IDS
    activity_show_output = ansible_module.pki(
        cli='tps-activity-show',
        nssdb=constants.NSSDB,
        port=constants.TPS_HTTP_PORT,
        protocol='http',
        certnick=certnick,
        extra_args=ACTIVITY_IDS[0]
    )
    for result in activity_show_output.values():
        for iter in expected:
            assert iter in result['stderr_lines']
