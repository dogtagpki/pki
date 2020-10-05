"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI SERVER CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki-server cli commands needs to be tested:
#   pki-server ca-audit-file-find
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
import random
import re
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
user_op = utils.UserOperations(nssdb=constants.NSSDB)


def test_pki_server_ca_audit_event_enable(ansible_module):
    """
    :id: 6254f633-e427-4481-8fb0-e67799004a7d
    :Title: Test pki-server ca-audit-event-enable command.
    :Description: Test pki-server ca-audit-event-enable command
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki-server ca-audit-event-enable
    :Expectedresults:
        1. It should throw an error message.
    """
    cmd = 'pki-server ca-audit-event-enable'
    cmd_out = ansible_module.shell(cmd)
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert "ERROR: Missing event name." in result['stderr']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run pki-server ca-audit-event-enable command.")
            pytest.fail()


def test_pki_server_ca_audit_event_enable_with_help_option(ansible_module):
    """
    :id: 96fd893e-7e48-41f0-9776-de1003e8f622
    :Title: Test pki-server ca-audit-event-enable with --help option.
    :Description: Test pki-server ca-audit-event-enable with --help option.
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki-server ca-audit-event-enable --help
    :Expectedresults:
        1. Command should show the help message.
    """
    cmd = 'pki-server ca-audit-event-enable --help'
    cmd_out = ansible_module.shell(cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Usage: pki-server ca-audit-event-enable [OPTIONS] <event_name>' in \
                   result['stdout']
            assert '-i, --instance <instance ID>       Instance ID (default: pki-tomcat).' in \
                   result['stdout']
            assert '-v, --verbose                      Run in verbose mode.' in result['stdout']
            assert '--help                         Show help message.' in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run pki-server ca-audit-event-enable --help command.")
            pytest.fail()


def test_pki_server_ca_audit_event_enable_with_valid_instance(ansible_module):
    """
    :id: 7db8ecec-97d6-4aa3-9dc6-fb3df0d4edd2
    :Title: Test pki-server ca-audit-envent-enable with valid instance.
    :Description: Test pki-server ca-audit-event-enable with valid instance.
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki-server ca-audit-event-enable -i <instance> AUTHZ
    :Expectedresults:
        1. It should configure the event.
    """
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
    else:
        instance = constants.CA_INSTANCE_NAME
    event = 'AUTHZ'
    cmd = 'pki-server ca-audit-event-enable -i {} {}'.format(instance, event)
    cmd_disable = 'pki-server ca-audit-event-disable -i {} {}'.format(instance,
                                                                      event)
    cmd_find = 'pki-server ca-audit-event-find -i {} --enabled True'.format(instance)
    cmd_out = ansible_module.shell(cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            if 'already enabled' in result['stdout']:
                assert 'Event "{}" may be already enabled.'.format(event) in result['stdout']
                log.info("Successfully run : {}".format(result['cmd']))
            else:
                assert 'Event "{}" enabled successfully. You may need to restart the ' \
                       'instance.'.format(event) in result['stdout']
                log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            pytest.fail()
    find_out = ansible_module.shell(cmd_find)
    for res in find_out.values():
        if res['rc'] == 0:
            assert 'Event Name: {}'.format(event) in res['stdout']
            assert 'Enabled: True' in res['stdout']
            assert 'Filter: None' in res['stdout']
            log.info("Successfully run : {}".format(res['cmd']))
        else:
            log.error("Failed to run pki-server ca-audit-event-find command.")
            pytest.fail()

    ansible_module.shell(cmd_disable)


def test_pki_server_ca_audit_event_enable_with_valid_instance_without_event(ansible_module):
    """
    :id: 512230e4-fe9c-45e6-a164-2bec246e8e49
    :Title: Test pki-server ca-audit-event-enable -i <instance> without filter
    :Description: Test pki-server ca-audit-event-enable -i <instance> without filter
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki-server ca-audit-event-enable -i <instance>
    :Expectedresults:
        1. It should show the error message.
    """
    cmd = 'pki-server ca-audit-event-enable -i {}'.format(constants.CA_INSTANCE_NAME)
    cmd_out = ansible_module.shell(cmd)
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert 'ERROR: Missing event name.' in result['stderr']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run pki-server ca-audit-event "
                      "-i {}".format(constants.CA_INSTANCE_NAME))
            pytest.fail()


def test_pki_server_ca_audit_event_enable_again_enable_it(ansible_module):
    """
    :id: b27ef942-aa7c-475b-8da6-ef8ca4655a75
    :Title: Test pki-server ca-audit-event-enable, enable it again.
    :Description: Test pki-server ca-audit-event-enable, enable it again.
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
            1. pki-server ca-audit-event-enable AUTHZ -i <instance>
            2. pki-server ca-audit-event-enable AUTHZ -i <instance>
    :Expectedresults:
            1. It should enable the event.
            2. It should print event already enabled message.
    """
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
    else:
        instance = constants.CA_INSTANCE_NAME
    event = 'RANDOM_GENERATION'
    disable_event = 'pki-server ca-audit-event-disable -i {} {}'.format(instance, event)
    enable_event = 'pki-server ca-audit-event-enable -i {} {}'.format(instance, event)

    disable_out = ansible_module.shell(disable_event)
    for res in disable_out.values():
        if res['rc'] == 0:
            if 'already disabled' not in res['stdout']:
                assert 'Audit event "{}" disabled. You may need to restart the ' \
                       'instance.'.format(event) in res['stdout']
                log.info("Successfully run : {}".format(res['cmd']))
        else:
            log.error("Failed to disable the event.")
            log.error("Failed to run : {}".format(res['cmd']))
    enable_out = ansible_module.shell(enable_event)
    for result in enable_out.values():
        if result['rc'] == 0:
            if 'already enabled' in result['stdout']:
                assert 'Event "{}" may be already enabled.'.format(event) in result['stdout']
            else:
                assert 'Event "{}" enabled successfully. ' \
                       'You may need to restart the instance.'.format(event) in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run pki-server ca-audit-event-enable "
                      "-i {} {}".format(instance, event))
            pytest.fail()

    enable_again = ansible_module.shell(enable_event)
    for result in enable_again.values():
        if result['rc'] == 0:
            assert 'Event "{}" may be already enabled.'.format(event) in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run pki-server ca-audit-event-enable "
                      "-i {} {}".format(constants.CA_INSTANCE_NAME, event))
            pytest.fail()


def test_pki_server_ca_audit_event_enable_check_log_after_enable(ansible_module):
    """
    :id: 03669fcf-3e57-4f09-8262-10638ee8c7c8
    :Title: Test pki-server ca-audit-event-enable, enable event and check the audit logs.
    :Description: Test pki-server ca-audit-event-enable, enable event and check the audit logs.
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
            1. Enable audit log event.
            2. Restart the instance.
            3. Enroll certificate, or any action which will trigger event.
    :Expectedresults:
            1. Event log should get successfully get logged in.
    """
    if TOPOLOGY == 1:
        instance = 'pki-tomcat'
    else:
        instance = constants.CA_INSTANCE_NAME
    event = 'RANDOM_GENERATION'
    filter = '(Outcome=*)'
    event_disbale = 'pki-server ca-audit-disable {} -i {}'.format(event, instance)
    remove_filter = 'pki-server ca-audit-event-update ' \
                    '-i {} {} --filter ""'.format(instance, event)
    enable_event = 'pki-server ca-audit-event-enable {} -i {}'.format(event,
                                                                      instance)
    enable_filter = 'pki-server ca-audit-event-update {} ' \
                    '--filter "{}" -i {}'.format(event, filter, instance)
    restart_instance = 'systemctl restart pki-tomcatd@{}'.format(instance)

    name = 'testuser' + str(random.randint(111, 9999))
    subject = '"UID={},CN={},C=IN"'.format(name, name)
    event_enable = ansible_module.shell(enable_event)
    for result in event_enable.values():
        if 'already enabled' not in result['stdout']:
            assert 'Event "{}" enabled. You may need to restart the ' \
                   'instance.'.format(event) in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            assert 'Event "{}" may be already enabled.'.format(event) in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))

    filter_enable = ansible_module.shell(enable_filter)
    for res in filter_enable.values():
        assert res['rc'] == 0
        log.info("Filter enabled for event: {}".format(event))
        log.info("Successfully run : {}".format(res['cmd']))

    ansible_module.shell(restart_instance)
    cert_id = user_op.process_certificate_request(ansible_module, subject=subject)
    log.info("Generated certificate : {}".format(cert_id))
    logs = ansible_module.shell('tail -n 30 /var/log/pki/{}/ca/'
                                'signedAudit/ca_audit'.format(instance))
    for log1 in logs.values():
        if log1['rc'] == 0:
            raw_logs = re.findall(r'\[AuditEvent=RANDOM_GENERATION\].*', log1['stdout'])
            a_logs = ",".join(raw_logs)
            assert 'RANDOM_GENERATION' in a_logs
            log.info("Found log RANDOM_GENERATION")
        else:
            log.error("Failed to get the log results.")
            log.error(log1['stderr'])
            pytest.fail()
    ansible_module.shell(event_disbale)
    ansible_module.shell(remove_filter)
    ansible_module.shell(restart_instance)
