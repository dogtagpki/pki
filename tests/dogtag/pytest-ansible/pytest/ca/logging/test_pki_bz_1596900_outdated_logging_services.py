#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Test outdated logging services
#                Bugzilla: 1596900: Outdated logging services
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Amol Kahat <akahat@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2019 Red Hat, Inc. All rights reserved.
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
import datetime
import logging
import os
import sys
import time

import pytest

from pki.testlib.common import utils

try:
    from pki.testlib.common import constants
except Exception:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
userop = utils.UserOperations(nssdb=constants.NSSDB)

LOGGING_PROPERTIES = '/etc/pki/{}/logging.properties'


def test_pki_bug_1596900_outdated_logging_services_with_warning(ansible_module):
    """
    :Title: Test BZ: 1596900 outdated logging services.
    :Description: Test BZ: 1596900 outdated logging services.
    :Requirement: Logging improvements
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Install CA
        2. Observe systemd journal
        3. Change the level to WARNING in /var/lib/pki/<instance>/conf/logging.properties
        4. Restart the server
    :ExpectedResults:
        1. Logs should show WARNING.
    """
    # journalctl -n 1000 -u pki-tomcatd@topology-ecc-CA -o short --no-pager --all
    ansible_module.lineinfile(path=LOGGING_PROPERTIES.format(constants.CA_INSTANCE_NAME),
                              regexp='^\.level.*',
                              line='.level = WARNING')
    ansible_module.command('systemctl restart pki-tomcatd@{}'.format(constants.CA_INSTANCE_NAME))

    cmd = 'journalctl -n 50 -u pki-tomcatd@{} -o short --no-pager --all'.format(constants.CA_INSTANCE_NAME)

    output = ansible_module.command(cmd)
    for result in output.values():
        if result['rc'] == 0:
            assert 'Stopped PKI Tomcat Server {}'.format(constants.CA_INSTANCE_NAME) in result['stdout']
            assert 'Started PKI Tomcat Server {}'.format(constants.CA_INSTANCE_NAME) in result['stdout']
            assert 'FINE: ' not in result['stdout']
            assert 'FINER: ' not in result['stdout']
            log.info("Not Found FINE: and FINER: logs in journalctl logs.")
        else:
            log.error("Failed to assert FINE: and FINER: logs in journalctl logs.")
            pytest.xfail()
    ansible_module.lineinfile(path=LOGGING_PROPERTIES.format(constants.CA_INSTANCE_NAME),
                              regexp='^\.level.*',
                              line='.level = WARNING')
    log.info("Resetting logging.properties file.")
    ansible_module.command('systemctl restart pki-tomcatd@{}'.format(constants.CA_INSTANCE_NAME))
    log.info("Restarting instance.")


def test_pki_bug_1596900_outdated_logging_services_with_fine(ansible_module):
    """
    :Title: Test BZ: 1596900 outdated logging services.
    :Description: Test BZ: 1596900 outdated logging services.
    :Requirement: Logging improvements
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Install CA
        2. Observe systemd journal
        3. Change the level to FINEST in /var/lib/pki/<instance>/conf/logging.properties
        4. Restart the server
    :ExpectedResults:
        1. Logs should show FINEST.
    """
    # journalctl -n 1000 -u pki-tomcatd@topology-ecc-CA -o short --no-pager --all
    ansible_module.lineinfile(path=LOGGING_PROPERTIES.format(constants.CA_INSTANCE_NAME),
                              regexp='^\.level.*',
                              line='.level = FINEST')
    ansible_module.command('systemctl restart pki-tomcatd@{}'.format(constants.CA_INSTANCE_NAME))

    cmd = 'journalctl -n 2000 -u pki-tomcatd@{} -o short --no-pager --all'.format(constants.CA_INSTANCE_NAME)
    time.sleep(20)
    output = ansible_module.command(cmd)
    for result in output.values():
        if result['rc'] == 0:
            assert 'FINE: ' in result['stdout']
            assert 'FINER: ' in result['stdout']
            log.info("Found FINE: and FINER: logs in journalctl logs.")
        else:
            log.error("Failed to assert FINE: and FINER: logs in journalctl logs.")
            pytest.xfail()
    ansible_module.lineinfile(path=LOGGING_PROPERTIES.format(constants.CA_INSTANCE_NAME),
                              regexp='^\.level.*',
                              line='.level = WARNING')
    log.info("Resetting logging.properties file.")
    ansible_module.command('systemctl restart pki-tomcatd@{}'.format(constants.CA_INSTANCE_NAME))
    log.info("Restarting instance.")


def test_pki_bug_1596900_check_rotational_debug_logs(ansible_module):
    """
    :Title: Test pki bug 1596900 check rotational debug logs
    :Description: Test bug 1596900 check rotational debug logs
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Issue certificate, It will generate debug logs.
        2. Debug log file with date should be generated.
        3. Change system date move it to one day ahead.
        4. Again issue the certificate. It should again generate Debug log file with date.
    :ExpectedResults:
        1. It should generate Debug log file with date.
    """
    CA_LOG_HOME = '/var/log/pki/{}/ca/debug.{}.log'
    today = datetime.datetime.today()
    tomorrow = (datetime.datetime.today() + datetime.timedelta(days=1))

    change_date = 'date -s "{}"'.format(tomorrow.strftime("%Y-%m-%d"))
    restore_date = 'date -s "{}"'.format(today.strftime("%Y-%m-%d"))

    subject_today = 'testuser_{}'.format(today.strftime("%Y-%m-%d"))
    subject_tomorrow = 'testuser_{}'.format(tomorrow.strftime("%Y-%m-%d"))
    cert_id = userop.process_certificate_request(ansible_module, subject=subject_today,
                                                 profile='caUserCert', keysize=2048)
    log.info("Created certificate with Cert ID: {}".format(cert_id))

    file_check = ansible_module.stat(path=CA_LOG_HOME.format(constants.CA_INSTANCE_NAME, today.strftime("%Y-%m-%d")))
    for r in file_check.values():
        try:
            assert r['stat']['exists']
            log.info("Log file '{}' generated.".format(CA_LOG_HOME.format(constants.CA_INSTANCE_NAME,
                                                                          today.strftime("%Y-%m-%d"))))
        except Exception as e:
            log.error("Log file 'debug.{}.log' is not present.".format(today.strftime("%Y-%m-%d")))
            log.error(e)
            pytest.xfail()
    out = ansible_module.command(change_date)
    for r in out.values():
        assert r['rc'] == 0
        log.info("Date changed to {}".format(today.strftime("%Y-%m-%d")))
        ansible_module.command('systemctl restart pki-tomcatd@{}'.format(constants.CA_INSTANCE_NAME))
        log.info("Restarted CA instance.")
    cert_id = userop.process_certificate_request(ansible_module, subject=subject_tomorrow,
                                                 profile='caUserCert', keysize=2048)
    log.info("Created certificate with Cert ID: {}".format(cert_id))

    file_check = ansible_module.stat(path=CA_LOG_HOME.format(constants.CA_INSTANCE_NAME,
                                                             tomorrow.strftime("%Y-%m-%d")))
    for r in file_check.values():
        try:
            assert r['stat']['exists']
            log.info("Log file '{}' generated.".format(CA_LOG_HOME.format(constants.CA_INSTANCE_NAME,
                                                                          tomorrow.strftime("%Y-%m-%d"))))
        except Exception as e:
            log.error("Log file is not present.")
            log.error(e)
            pytest.xfail()
    out = ansible_module.command(restore_date)
    for r in out.values():
        assert r['rc'] == 0
        log.info("Date restored to {}".format(today.strftime("%Y-%m-%d")))
        ansible_module.command('systemctl restart pki-tomcatd@{}'.format(constants.CA_INSTANCE_NAME))
        log.info("Restarted CA instance.")
