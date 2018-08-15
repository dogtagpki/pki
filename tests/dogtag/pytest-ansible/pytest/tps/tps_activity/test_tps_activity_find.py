#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Automation for tps-activity-find CLI
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

HOST = 'pki1.example.com'

@pytest.mark.ansible_playbook_setup('ldapUserAdd.yml', 'enablePinReset.yml',
                                    'tokenFormat.yml', 'tokenEnroll.yml', 'tokenPinReset.yml')
@pytest.mark.setup
def test_setup(ansible_playbook, ansible_module):
    #the above mentioned ansible playbooks are called as a part of test setup
    global HOST
    cert_setup = CertSetup(nssdb=constants.NSSDB,
                           db_pass=constants.CLIENT_DATABASE_PASSWORD,
                           host=HOST,
                           port=constants.CA_HTTP_PORT,
                           nick="'{}'".format(constants.CA_ADMIN_NICK))
    cert_setup.create_certdb(ansible_module)
    cert_setup.import_ca_cert(ansible_module)
    cert_setup.import_admin_p12(ansible_module, 'ca')
    cert_setup.setup_role_users(ansible_module, 'ca', constants.CA_ADMIN_NICK, duration='minute')
    tps_cert_setup = CertSetup(nssdb=constants.NSSDB,
                               db_pass=constants.CLIENT_DATABASE_PASSWORD,
                               host=HOST,
                               port=constants.TPS_HTTP_PORT,
                               nick="'{}'".format(constants.TPS_ADMIN_NICK))
    tps_cert_setup.import_admin_p12(ansible_module, 'tps')
    tps_cert_setup.setup_role_users(ansible_module, 'tps', constants.TPS_ADMIN_NICK,
                                    duration='minute')


def test_tpsactivity_find_help(ansible_module):
    """
    :Title: Run tps-activity-find help

    :Description: Run tps-activity-find help

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
    activity_help_output = ansible_module.command('pki tps-activity-find --help')
    for result in activity_help_output.values():
        assert "--help            Show help options" in result['stdout']
        assert "--size <size>     Page size" in result['stdout']
        assert "--start <start>   Page start" in result['stdout']

@pytest.mark.parametrize("certnick,expected", [
    ("TPS_AdminV", ["User ID: jdoe", "Token ID: %s" % constants.CUID, "Operation: enrollment",
                    "Result: success", "Operation: format", "Operation: pin_reset",
                    "Operation: enrollment"]),
    ("TPS_AgentV", ["User ID: jdoe", "Token ID: %s" % constants.CUID, "Operation: enrollment",
                    "Result: success", "Operation: format", "Operation: pin_reset",
                    "Operation: enrollment"]),
    ("TPS_OperatorV", ["User ID: jdoe", "Token ID: %s" % constants.CUID, "Operation: enrollment",
                       "Result: success", "Operation: format", "Operation: pin_reset",
                       "Operation: enrollment"]),
])
def test_tpsactivity_find_validnicks(ansible_module, certnick, expected):
    """
    :Title: Run tps-activity-find with valid certnicks

    :Description: Run tps-activity-find with valid certnicks

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
    activity_find_output = ansible_module.pki(
        cli='tps-activity-find',
        nssdb=constants.NSSDB,
        port=constants.TPS_HTTP_PORT,
        protocol='http',
        certnick=certnick,
    )
    result = None
    activity_ids = None
    for result in activity_find_output.values():
        activity_ids = re.findall("Activity ID\: [0-9]+\.[0-9]+", result['stdout'])
        activity_ids = [item.split(':')[1].strip() for item in activity_ids]

    for item in activity_ids:
        assert "Activity ID: %s" % item in result['stdout']

    for result in activity_find_output.values():
        for iter in expected:
            assert iter in result['stdout']


@pytest.mark.parametrize("certnick,expected", [
    ("TPS_AdminR", ["FATAL: SSL alert received: CERTIFICATE_REVOKED"]),
    ("TPS_AdminE", ["FATAL: SSL alert received: CERTIFICATE_EXPIRED"]),
    ("TPS_AgentR", ["FATAL: SSL alert received: CERTIFICATE_REVOKED"]),
    ("TPS_AgentE", ["FATAL: SSL alert received: CERTIFICATE_EXPIRED"]),
    ("TPS_OperatorR", ["FATAL: SSL alert received: CERTIFICATE_REVOKED"]),
    ("TPS_OperatorE", ["FATAL: SSL alert received: CERTIFICATE_EXPIRED"]),
])
def test_tpsactivity_find_othernicks(ansible_module, certnick, expected):
    """
    :Title: Run tps-activity-find with expired and revoked certnicks

    :Description: Run tps-activity-find with expired and revoked certnicks

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
    activity_find_output = ansible_module.pki(
        cli='tps-activity-find',
        nssdb=constants.NSSDB,
        port=constants.TPS_HTTP_PORT,
        protocol='http',
        certnick=certnick,
    )
    for result in activity_find_output.values():
        for iter in expected:
            assert iter in result['stderr_lines']
