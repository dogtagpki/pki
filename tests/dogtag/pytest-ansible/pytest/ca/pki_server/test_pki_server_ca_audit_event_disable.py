"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI SERVER  CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki-server cli commands needs to be tested:
#   pki-server ca-audit-event-disable
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

TOPOLOGY = int(constants.CA_INSTANCE_NAME.split("-")[-2])
log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
userop = utils.UserOperations(nssdb=constants.NSSDB)


def test_pki_server_ca_audit_event_disable(ansible_module):
    """
    :id: 4d31a96c-fea7-4935-bdc7-c65664f86853
    :Title: Test pki-server ca-audit-event-disable command.
    :Description: Test pki-server ca-audit-event-disable command
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki-server ca-audit-event-disable
    :Expectedresults:
        1. It should throw an error message.
    """
    cmd = 'pki-server ca-audit-event-disable'
    cmd_out = ansible_module.shell(cmd)
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert "ERROR: Missing event name." in result['stderr']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()


def test_pki_server_ca_audit_event_disable_help(ansible_module):
    """
    :id: 40574145-c56b-478b-83ad-404d76bcb05f
    :Title: Test pki-server ca-audit-event-disable --help CLI
    :Description: Test pki-server ca-audit-event-disable --help CLI
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki-server ca-audit-event-disable --help
    :Expectedresults:
        1. It should show the help message.
    """

    cmd = 'pki-server ca-audit-event-disable --help'
    cmd_out = ansible_module.shell(cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Usage: pki-server ca-audit-event-disable [OPTIONS] <event_name>' in \
                   result['stdout']
            assert '-i, --instance <instance ID>       Instance ID (default: pki-tomcat).' in \
                   result['stdout']
            assert '-v, --verbose                      Run in verbose mode.' in result['stdout']
            assert '--help                         Show help message.' in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run pki-server ca-audit-event-disable --help command.")
            pytest.fail()


def test_pki_server_ca_audit_event_disable_with_valid_instance(ansible_module):
    """
    :id: 0f667b67-3e7a-414f-b609-4973a39f1a7c
    :Title: Test pki-server ca-audit-event-disable with valid instance
    :Description: Test pki-server ca-audit-event-disable with valid instance
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki-server ca-audit-event-disable -i <instance> AUTHZ
    :Expectedresults:
        1. It should disable the audit event
    """
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
    else:
        instance = constants.CA_INSTANCE_NAME
    event = 'AUTHZ'
    cmd = 'pki-server ca-audit-event-disable -i {} AUTHZ'.format(instance)
    cmd_out = ansible_module.shell(cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            if 'already disabled' not in result['stdout']:
                assert 'Audit event "{}" disabled. You may need to restart the ' \
                       'instance.'.format(event) in result['stdout']
                log.info("Successfully run : {}".format(result['cmd']))
            else:
                assert 'Audit event "{}" already disabled.'.format(event) in result['stdout']
                log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run pki-server ca-audit-event-disable with valid instance.")
            pytest.fail()


def test_pki_server_ca_audit_event_disable_with_invalid_instance(ansible_module):
    """
    :id: a387f11d-149d-45ac-83a1-c0e78423877f
    :Title: Test pki-server ca-audit-event-disable with invalid instance.
    :Description: Test pki-server ca-audit-event with invalid instance.
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki-server ca-audit-event-disable -i ROOTCA AUTHZ
    :Expectedresults:
        1. It should show an error message.
    """
    event = 'AUTHZ'
    cmd = 'pki-server ca-audit-event-disable -i ROOTCA {}'.format(event)
    cmd_out = ansible_module.shell(cmd)
    for result in cmd_out.values():
        if result['rc'] >= 0:
            assert 'ERROR: Invalid instance ROOTCA.' in result['stderr']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run pki-server ca-audit-event-disable -i ROOTCA {}".format(event))
            pytest.fail()


def test_pki_server_ca_audit_event_disable_with_already_disabled_event(ansible_module):
    """
    :id: 83702828-4549-495d-8d10-8f92600ad33b
    :Title: Test pki-server ca-audit-event-disable with already disabled event.
    :Description: Test pki-server ca-audit-event-disable with already disabled event.
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki-server ca-audit-event-disable -i <instance> AUTHZ
        2. pki-server ca-audit-event-disable -i <instance> AUTHZ
    :Expectedresults:
            1. It should show event already disabled message.
    """
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
    else:
        instance = constants.CA_INSTANCE_NAME
    event = 'AUTHZ'
    cmd = 'pki-server ca-audit-event-disable {} -i {}'.format(event, instance)
    ansible_module.shell(cmd)
    cmd_out = ansible_module.shell(cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Audit event "{}" already disabled.'.format(event) in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run pki-server ca-audit-event-disable AUTHZ")
            pytest.fail()
    ansible_module.command('pki-server ca-audit-envent-enable {} -i {}'.format(event, constants.CA_INSTANCE_NAME))


def test_pki_server_ca_audit_event_disable_when_event_filter_is_present(ansible_module):
    """
    :id: b5b846d7-4ac2-45f3-a849-52993e94534f
    :Title: Test pki-server ca-audit-event-disable when filter is configured.
    :Description: Test pki-server ca-audit-event-disable with filter is configured.
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Enable the audit event.
        2. configure the filter for the audit event.
        3. Disable the audit event.
    :Expectedresults:
        1. Event should get successfully disabled.
    """
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
    else:
        instance = constants.CA_INSTANCE_NAME
    event = 'RANDOM_GENERATION'
    filter = '(Outcome=*)'
    event_disable = 'pki-server ca-audit-disable {} -i {}'.format(event, instance)
    remove_filter = 'pki-server ca-audit-event-update ' \
                    '-i {} {} --filter ""'.format(instance, event)
    enable_event = 'pki-server ca-audit-event-enable {} -i {}'.format(event,
                                                                      instance)
    enable_filter = 'pki-server ca-audit-event-update {} ' \
                    '--filter "{}" -i {}'.format(event, filter, instance)
    restart_instance = 'systemctl restart pki-tomcatd@{}'.format(instance)

    event_enable = ansible_module.shell(enable_event)
    for result in event_enable.values():
        if result['rc'] == 0:
            if 'already enabled' in result['stdout']:
                assert 'Event "{}" may be already enabled'.format(event) in result['stdout']
            else:
                assert 'Audit event "{}" enabled. You may need to restart the instance' in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))
    filter_enable = ansible_module.shell(enable_filter)
    for res in filter_enable.values():
        assert res['rc'] == 0
        log.info("Successfully run : {}".format(res['cmd']))
    ansible_module.shell(restart_instance)

    disable_event = ansible_module.shell(event_disable)
    for result in disable_event.values():
        if result['rc'] == 0:
            if 'already disabled' not in result['stdout']:
                assert 'Audit event "{}" disabled. You may need to restart the ' \
                       'instance.'.format(event) in result['stdout']
                log.info("Successfully run : {}".format(result['cmd']))
            else:
                assert 'Event "{}" already disabled.'.format(event) in result['stdout']
                log.info("Successfully run : {}".format(result['cmd']))

    ansible_module.shell(remove_filter)
    ansible_module.shell(restart_instance)
