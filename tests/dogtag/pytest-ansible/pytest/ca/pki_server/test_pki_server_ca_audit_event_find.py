"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI SERVER  CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki-server cli commands needs to be tested:
#   pki-server ca-audit-event-find
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

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

TOPOLOGY = int(constants.CA_INSTANCE_NAME.split("-")[-2])
log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)


def test_pki_server_ca_audit_event_find(ansible_module):
    """
    :id: bcecc680-1c68-4119-b414-269762663b4c
    :Title: Test pki-server ca-audit-event-find command
    :Description: Test pki-server ca-audit-event-find command
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki-server ca-audit-event-find
    :Expectedresults:
        1. It should show the error message.
    """
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
    else:
        instance = constants.CA_INSTANCE_NAME
    cmd = 'pki-server ca-audit-event-find -i {}'.format(instance)

    cmd_out = ansible_module.shell(cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Event Name:' in result['stdout']
            assert 'Enabled:' in result['stdout']
            log.info("Successfully ran: {}".format(result['cmd']))
        else:
            log.error("Failed to run pki-server ca-audit-event-find command.")
            pytest.fail()


def test_pki_server_ca_audit_event_find_with_help(ansible_module):
    """
    :id: f27ee83c-385d-41b7-a74a-e41f4649a93c
    :Title: Test pki-server ca-audit-event-find command with --help option
    :Description: Test pki-server ca-audit-event-find command with --help option.
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki-server ca-audit-event-find --help
    :Expectedresults:
        1. It should show the help message.
    """

    cmd = 'pki-server ca-audit-event-find --help'

    cmd_out = ansible_module.shell(cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Usage: pki-server ca-audit-event-find [OPTIONS]' in result['stdout']
            assert '  -i, --instance <instance ID>         Instance ID (default: pki-tomcat).' in result['stdout']
            assert '      --enabled <True|False>           Show events currently enabled/disabled only.' in result['stdout']
            assert '      --enabledByDefault <True|False>  Show events enabled/disabled by default only.' in result['stdout']
            assert '  -v, --verbose                        Run in verbose mode.' in result['stdout']
            assert '      --debug                          Run in debug mode.' in result['stdout']
            assert '      --help                           Show help message.' in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            pytest.fail()


def test_pki_server_ca_audit_event_find_with_args(ansible_module):
    """
    :id: c602be02-2f03-45dc-ab92-c8528f2c6ed0
    :Title: Test pki-server ca-audit-event-find with arguments.
    :Description: Test pki-server ca-audit-event-find with arguments
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki-server ca-audit-event-find -i {} --enabled True
    :Expectedresults:
        1. It should show the available audit events.
    """
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
    else:
        instance = constants.CA_INSTANCE_NAME
    cmd = 'pki-server ca-audit-event-find -i {} --enabled True'.format(instance)
    cmd_out = ansible_module.shell(cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'entries matched' in result['stdout']
            assert 'Event Name:' in result['stdout']
            assert 'Enabled: True' in result['stdout']
            assert 'Filter:' in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            pytest.fail()


def test_pki_server_ca_audit_event_find_with_enabled_false(ansible_module):
    """
    :id: c3d615f1-d14e-4e4a-b26b-7b0c6ae11049
    :Title: Test pki-server ca-audit-event-find with --enabled False
    :Description: Test pki-server ca-audit-event-find with --enabled False
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki-server ca-audit-event-find -i <instance> --enable False
    :Expectedresults:
        1. It should show error message.
    """
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
    else:
        instance = constants.CA_INSTANCE_NAME
    cmd = 'pki-server ca-audit-event-find -i {} --enabled False'.format(instance)
    cmd_out = ansible_module.shell(cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'entries matched' in result['stdout']
            assert 'Event Name:' in result['stdout']
            assert 'Enabled: False' in result['stdout']
            assert 'Filter:' in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run pki-server ca-audit-event-find with --enable False.")
            pytest.fail()


def test_pki_server_ca_audit_event_find_with_invalid_instance(ansible_module):
    """
    :id: a00c9ccb-f6b0-42cf-b215-1d480df72108
    :Title: Test pki-server ca-audit-event-find with invalid instance.
    :Description: Test pki-server ca-audit-event-find with invalid instance.
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki-server ca-audit-event-find -i invalid_instance
    :Expectedresults:
        1. It should throw an error messages.
    """
    cmd = 'pki-server ca-audit-event-find -i invalid_instance'
    cmd_out = ansible_module.shell(cmd)
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert 'ERROR: Invalid instance invalid_instance' in result['stderr']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run pki-server ca-audit-event-find with invalid instance.")
            pytest.fail()


def test_pki_server_ca_audit_event_find_after_enabling_event(ansible_module):
    """
    :id: 060c1254-87d0-45f3-8250-09c17fcfe861
    :Title: Test find audit event after enableing the audit event.
    :Description: Enable audit event, and audit find should show the event.
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki-server ca-audit-event-enable -i <instance> RANDOM_GENERATION
        2. pki-server ca-audit-event-find -i <instance>
    :Expectedresults:
        1. Find command should show the event.
    """
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
    else:
        instance = constants.CA_INSTANCE_NAME
    event = 'RANDOM_GENERATION'
    enable_event = 'pki-server ca-audit-event-enable ' \
                   '-i {} {}'.format(instance, event)
    disable_event = 'pki-server ca-audit-event-disable ' \
                    '-i {} {}'.format(instance, event)
    event_find = 'pki-server ca-audit-event-find -i {}'.format(instance)

    enable_out = ansible_module.shell(enable_event)
    for result in enable_out.values():
        if result['rc'] == 0:
            if 'already enabled' not in result['stdout']:
                assert 'Event "{}" enabled successfully. You may need to restart the ' \
                       'instance'.format(event) in result['stdout']
                log.info("Successfully run : {}".format(result['cmd']))
            else:
                assert 'Event "{}" may be already enabled.'.format(event) in result['stdout']
                log.info("Successfully run : {}".format(result['cmd']))
        else:
            pytest.fail("Failed to enable the audit event.")
    find_out = ansible_module.shell(event_find)
    for res in find_out.values():
        if res['rc'] == 0:
            assert 'Event Name: {}'.format(event) in res['stdout']
            assert 'Enabled: True' in res['stdout']
            assert 'Filter:' in res['stdout']
            log.info("Successfully run : {}".format(res['cmd']))
        else:
            log.error("Failed to run pki-server ca-audit-event-find.")
            pytest.fail()
    ansible_module.shell(disable_event)
