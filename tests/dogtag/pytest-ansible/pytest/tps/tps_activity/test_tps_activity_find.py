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
import random
import pytest
import logging
import re
import time

from pki.testlib.common.certlib import CertSetup

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

userid = 'testuser{}'.format(random.randint(1, 9999))

topology = constants.TPS_INSTANCE_NAME.split("-")[1].strip()

if topology == "01":
    instance_name = 'pki-tomcat'
else:
    instance_name = constants.TPS_INSTANCE_NAME

BASE_DIR = '/var/lib/pki/'
tps_cfg_path = BASE_DIR + '/' + instance_name + '/' + 'tps/conf/CS.cfg'

ldap_path = "/tmp/test_dir/ldap_user_add.cfg"
format_path = '/tmp/test_dir/token_format.txt'
enroll_path = '/tmp/test_dir/token_enroll.txt'

disable_reset = 'tokendb.defaultPolicy=RE_ENROLL=YES;RENEW=NO;FORCE_FORMAT=NO;PIN_RESET=NO;RESET_PIN_RESET_TO_NO=NO'
enable_reset = 'tokendb.defaultPolicy=RE_ENROLL=YES;RENEW=NO;FORCE_FORMAT=NO;PIN_RESET=YES;RESET_PIN_RESET_TO_NO=NO'


@pytest.mark.setup
def test_setup(ansible_module):
    '''
          :Title: Test for running tps-activity-find command.
          :Description: This is test for tps-activity-find command.


          :Type: Functional
          :steps:

          1. Create custom nssdb and import Admin certificates.
          2. Create role Users for CA and TPS (i.e CA_AdminV, CA_AdminE, CA_AdminR) and import role users certificates in custom database.
          3. Add LDAP user.
          4. Update TPS configuration file.
          5. Update LDAP user and CUID details in token_format.txt and token_enroll.txt
          6. Format and Enroll Token.
          7. Run tps-activity-find command , with Valid, Expired and  Revoked Certificate Nickname which are imported in custom NSSDB.

          :setup:
          1. Install CA, KRA, OCSP, TKS and TPS


          :Expected Results:
          1. Installation is successful.
          2. tps-activity-find and tps-activity-show command should succeed with Valid Certificate Nicknames.
          3. tps-activity-find and tps-activity-show command should fail to run with Expired and Revoked Certificate Nicknames.

    '''
    cert_setup = CertSetup(nssdb=constants.NSSDB,
                           db_pass=constants.CLIENT_DATABASE_PASSWORD,
                           host=constants.MASTER_HOSTNAME,
                           port=constants.CA_HTTP_PORT,
                           nick="'{}'".format(constants.CA_ADMIN_NICK))
    cert_setup.create_certdb(ansible_module)
    cert_setup.import_ca_cert(ansible_module)
    cert_setup.import_admin_p12(ansible_module, 'ca')
    cert_setup.setup_role_users(ansible_module, 'ca', duration='minute')
    tps_cert_setup = CertSetup(nssdb=constants.NSSDB,
                               db_pass=constants.CLIENT_DATABASE_PASSWORD,
                               host=constants.MASTER_HOSTNAME,
                               port=constants.TPS_HTTP_PORT,
                               nick="'{}'".format(constants.TPS_ADMIN_NICK))
    tps_cert_setup.import_admin_p12(ansible_module, 'tps')
    tps_cert_setup.setup_role_users(ansible_module, 'tps', duration='minute')

    def stop_instance(ansible_module, instance=instance_name):
        command = 'systemctl stop pki-tomcatd@{}'.format(instance)
        out = ansible_module.shell(command)
        for res in out.values():
            assert res['rc'] == 0

    stop_instance(ansible_module)
    time.sleep(5)

    ansible_module.lineinfile(dest=tps_cfg_path, regexp=disable_reset, line=enable_reset)


    def start_instance(ansible_module, instance=instance_name):
        command = 'systemctl start pki-tomcatd@{}'.format(instance)
        out = ansible_module.shell(command)
        for res in out.values():
            assert res['rc'] == 0

    start_instance(ansible_module)
    time.sleep(5)

    for path in ldap_path, format_path, enroll_path:
        for content in constants.LDAP_USER1, 'CUID':
            if content == constants.LDAP_USER1:
                ansible_module.replace(path=path, regexp=content, replace=userid)
            else:
                ansible_module.replace(path=path, regexp='CUID', replace=constants.CUID)


    # Creating ldap user
    ldap_user_out = ansible_module.shell('ldapadd -h {} -p {} -D "cn=Directory Manager" -w {} -f {}'
                                         ''.format(constants.MASTER_HOSTNAME, constants.LDAP_PORT,
                                                   constants.LDAP_PASSWD,
                                                   ldap_path))
    for result in ldap_user_out.values():
        if result['rc'] == 0:
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.fail()

    time.sleep(5)

    format_token = ansible_module.shell('tpsclient < {}'.format(format_path))
    time.sleep(5)
    enroll_token = ansible_module.shell('tpsclient < {}'.format(enroll_path))
    time.sleep(5)

    # Enroll tps token
    for result in enroll_token.values():
        if result['rc'] == 1:
            assert "Result> Success - Operation 'ra_enroll' Success" in result['stdout']
            log.info('Successfully enrolled the token with : {}'.format(result['cmd']))
        else:
            assert result['rc'] > 1
            log.error('Failed to ran : {}'.format(result['cmd']))
            pytest.fail(result['stdout'])
            pytest.fail(result['stderr'])


def test_tpsactivity_find_help(ansible_module):
    """
    :Title: Run tps-activity-find help

    :Description: Run tps-activity-find help

    :Requirement: RHCS-REQ TPS Server CLI Tests

    :Setup:
        Use subsystems setup via ansible playbooks

    :Steps:
        Setup RHCS using ansible playbooks

    :Expectedresults:
        RHCS should be setup via ansible playbooks

    :Automated: Yes

    :CaseComponent: \-
    """
    activity_help_output = ansible_module.command('pki tps-activity-find --help')
    for result in activity_help_output.values():
        assert "--help            Show help message" in result['stdout']
        assert "--size <size>     Page size" in result['stdout']
        assert "--start <start>   Page start" in result['stdout']
    time.sleep(5)


@pytest.mark.parametrize("certnick", ["TPS_AdminV","TPS_AgentV","TPS_AuditV"])

def test_tpsactivity_find_validnicks(ansible_module, certnick):
    """
    :Title: Run tps-activity-find with valid certnicks

    :Description: Run tps-activity-find with valid certnicks

    :Requirement: RHCS-REQ TPS Server CLI Tests

    :Setup:
        Use subsystems setup via ansible playbooks

    :Steps:
        Setup RHCS using ansible playbooks

    :Expectedresults:
        RHCS should be setup via ansible playbooks

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


    for result in activity_find_output.values():
        if result['rc'] == 0:
            for item in activity_ids:
                assert "Activity ID: %s" % item in result['stdout']
                assert "entries matched" in result['stdout']
                log.info("Successfully Run : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail("Failed to Run : {}".format(result['cmd']))
    time.sleep(5)


@pytest.mark.parametrize("certnick,expected", [
    ("TPS_AdminE", ["SEVERE: FATAL: SSL alert received: CERTIFICATE_EXPIRED"]),
    ("TPS_AgentE", ["SEVERE: FATAL: SSL alert received: CERTIFICATE_EXPIRED"]),
    ("TPS_AuditE", ["SEVERE: FATAL: SSL alert received: CERTIFICATE_EXPIRED"]),
])
def test_tpsactivity_find_othernicks_expired(ansible_module, certnick,expected):
    """
    :Title: Run tps-activity-find with expired certnicks

    :Description: Run tps-activity-find with expired and revoked certnicks

    :Requirement: RHCS-REQ TPS Server CLI Tests

    :Setup:
        Use subsystems setup via ansible playbooks

    :Steps:
        Setup RHCS using ansible playbooks

    :Expectedresults:
        RHCS should be setup via ansible playbooks

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
    time.sleep(5)


@pytest.mark.parametrize("revoked_user_cert", ["TPS_AdminR", "TPS_AgentR", "TPS_AuditR"])


def test_tpsactivity_find_othernicks_revoked(ansible_module, revoked_user_cert):
    """
        :Title: Run tps-activity-find with revoked certnicks

        :Description: Run tps-activity-find with  revoked certnicks

        :Requirement: RHCS-REQ TPS Server CLI Tests

        :Setup:
            Use subsystems setup via ansible playbooks

        :Steps:
            Setup RHCS using ansible playbooks

        :Expectedresults:
            RHCS should be setup via ansible playbooks

        :Automated: Yes

        :CaseComponent: \-
     """

    activity_find_output = ansible_module.pki(
        cli='tps-activity-find',
        nssdb=constants.NSSDB,
        port=constants.TPS_HTTP_PORT,
        protocol='http',
        certnick='"{}"'.format(revoked_user_cert),
    )
    for result in activity_find_output.values():
        if result['rc'] == 0:
            assert 'entries matched' in result['stdout']
            assert 'Number of entries returned' in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
            pytest.skip('BZ: https://bugzilla.redhat.com/show_bug.cgi?id=1699059')
        elif result['rc'] >= 1:
            assert 'SEVERE: FATAL: SSL alert received: CERTIFICATE_REVOKED' in result['stderr']   # change the assertion once the BZ 1699059 fixed
            log.info('Successfully ran : {}'.format(result['cmd']))


