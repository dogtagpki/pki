"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI-SERVER CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki-server instance-externalcert commands needs to be tested:
#   pki-server instance-externalcert-del --help
#   pki-server instance-externalcert-del
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

import random
import sys

import os
import pytest

from pki.testlib.common import utils

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants
userop = utils.UserOperations(nssdb=constants.NSSDB)

BASE_DB_DIR = '/var/lib/pki/{}/alias'


def create_cert(ansible_module):
    """
    Return a base 64 encoded certificate.
    """
    # pass_file = '/var/lib/pki/{}/conf/password.conf'.format(constants.CA_INSTANCE_NAME)
    # internal_pass = ''
    no = random.randint(11, 999989)
    user = 'testuser{}'.format(no)
    subject = 'UID={},CN={}'.format(user, user)

    cert_id = userop.process_certificate_request(ansible_module, subject=subject)
    if cert_id:
        cert_file = "/tmp/{}.pem".format(user)
        ansible_module.command('pki -d {} -c {} -p {} client-cert-import "{}" '
                               '--serial {}'.format(constants.NSSDB, constants.CLIENT_DIR_PASSWORD,
                                                    constants.CA_HTTP_PORT, user, cert_id))
        ansible_module.command('pki -d {} -c {} client-cert-show "{}" '
                               '--cert /tmp/{}.pem '.format(constants.NSSDB,
                                                            constants.CLIENT_DIR_PASSWORD,
                                                            user, user))
        return [cert_id, cert_file]


def test_pki_server_instance_externalcert_del_help_command(ansible_module):
    """
    :id: fa751f20-f2f2-4f29-bf92-b9f755f6f2ad
    :Title: Test pki-server instance-externalcert-del --help command, BZ:1339263
    :Description: test pki-server instance-externalcert-del --help command, This test also verifies 
     bugzilla id : 1339263
    :CaseComponent: \-
    :Requirement: Pki Server Instance
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults: 
        1. Verify whether pki-server instance-externalcert-del --help command shows the 
        following output.
            Usage: pki-server instance-externalcert-del [OPTIONS]
        
            -i, --instance <instance ID>       Instance ID (default: pki-tomcat).
            --nickname <nickname>          Nickname to be used.
            --token <token_name>           Token (default: internal).
            -v, --verbose                      Run in verbose mode.
            --help                         Show help message.
    """
    help_cmd = 'pki-server instance-externalcert-del --help'

    cmd_output = ansible_module.command(help_cmd)
    for result in cmd_output.values():
        if result['rc'] == 0:
            assert "Usage: pki-server instance-externalcert-del [OPTIONS]" in result['stdout']
            assert "-i, --instance <instance ID>       Instance ID (default: pki-tomcat)." in \
                   result['stdout']
            assert "--nickname <nickname>          Nickname to be used." in result['stdout']
            assert "--token <token_name>           Token (default: internal)." in \
                   result['stdout']
            assert "-v, --verbose                      Run in verbose mode." in \
                   result['stdout']
            assert "--help                         Show help message." in result['stdout']

        else:
            pytest.xfail("Failed to run pki-server instance-externalcert-del --help command")


def test_pki_server_instance_externalcert_del_command(ansible_module):
    """
    :id: 496bee04-9e13-4821-9467-be928128f50c
    :Title: Test pki-server instance-externalcert-del command
    :Description: test pki-server instance-externalcert-del command
    :CaseComponent: \-
    :Requirement: Pki Server Instance
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server instance-externalcert-del command delete the certificate
        from the instance.
    """
    cert_id, cert_file = create_cert(ansible_module)
    user_id = cert_file.split("/")[-1].split(".")[0]

    cert_add = 'pki-server instance-externalcert-add -i {} --cert-file {} --trust-args ' \
               '"u,u,u" --nickname "{}" --token internal'.format(constants.CA_INSTANCE_NAME,
                                                                 cert_file, user_id)

    del_cert = 'pki-server instance-externalcert-del -i {} --nickname "{}" ' \
               '--token internal'.format(constants.CA_INSTANCE_NAME, user_id)

    certutil_cmd = 'certutil -L -d {} | ' \
                   'grep \"{}\"'.format(BASE_DB_DIR.format(constants.CA_INSTANCE_NAME), user_id)

    cmd_output = ansible_module.command(cert_add)
    for result in cmd_output.values():
        if result['rc'] == 0:
            assert "Certificate imported for instance " + constants.CA_INSTANCE_NAME \
                   in result['stdout']
        else:
            assert "ERROR: Certificate already imported for instance %s." % \
                   constants.CA_INSTANCE_NAME in result['stdout']

    certImported = ansible_module.command(certutil_cmd)
    for res in certImported.values():
        if res['rc'] == 0:
            assert user_id in res['stdout']

    cmd_output = ansible_module.command(del_cert)
    for result in cmd_output.values():
        if result['rc'] == 0:
            assert "Certificate removed from instance " + constants.CA_INSTANCE_NAME + "." in \
                   result['stdout']

        else:
            pytest.xfail("Failed to run pki-server instance-externalcert-del command")


def test_pki_server_instance_externalcert_del_when_instance_is_stopped(ansible_module):
    """
    :id: b78d6ef9-3438-44f6-998c-ea1795da490f
    :Title: Test pki-server instance-externalcert-del when instance is stopped
    :Description: test pki-server instance-externalcert-del command
    :CaseComponent: \-
    :Requirement: Pki Server Instance
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server instance-externalcert-del command delete the certificate to
        the instance when instance is stopped.
    """

    cert_id, cert_file = create_cert(ansible_module)
    user_id = cert_file.split("/")[-1].split(".")[0]

    instance = constants.CA_INSTANCE_NAME
    stop_instance = 'pki-server instance-stop {}'.format(instance)
    start_instance = 'pki-server instance-start {}'.format(instance)
    ansible_module.command(stop_instance)

    cert_add = 'pki-server instance-externalcert-add -i {} --cert-file {} --trust-args ' \
               '"u,u,u" --nickname "{}" --token internal'.format(constants.CA_INSTANCE_NAME,
                                                                 cert_file, user_id)

    del_cert = 'pki-server instance-externalcert-del -i {} --nickname "{}" ' \
               '--token internal'.format(constants.CA_INSTANCE_NAME, user_id)

    certutil_cmd = 'certutil -L -d {} | ' \
                   'grep \"{}\"'.format(BASE_DB_DIR.format(constants.CA_INSTANCE_NAME), user_id)

    cmd_output = ansible_module.command(cert_add)
    for result in cmd_output.values():
        if result['rc'] == 0:
            assert "Certificate imported for instance " + constants.CA_INSTANCE_NAME \
                   in result['stdout']
        else:
            assert "ERROR: Certificate already imported for instance %s." % \
                   constants.CA_INSTANCE_NAME in result['stdout']

    certImported = ansible_module.command(certutil_cmd)
    for res in certImported.values():
        if res['rc'] == 0:
            assert user_id in res['stdout']

    cmd_output = ansible_module.command(del_cert)
    for result in cmd_output.values():
        if result['rc'] == 0:
            assert "Certificate removed from instance " + constants.CA_INSTANCE_NAME + "." in \
                   result['stdout']

        else:
            pytest.xfail("Failed to run pki-server instance-externalcert-del command")
    ansible_module.command(start_instance)


def test_pki_server_instance_externalcert_del_with_token_NHSM6000(ansible_module):
    """
    :id: e25f9d90-aa85-4579-bcb9-867bdd7acb68
    :Title: Test pki-server instance-externalcert-del with NHSM6000 token
    :Description: test pki-server instance-externalcert-del command
    :CaseComponent: \-
    :Requirement: Pki Server Instance
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server instance-externalcert-del command delete the certificate to
        the instance when the token is NHSM6000.
    """

    cert_id, file_name = create_cert(ansible_module)
    user_id = file_name.split("/")[-1].split(".")[0]

    certificate_add_cmd = 'pki-server instance-externalcert-add -i {} --cert-file {} ' \
                          '--token NHSM6000 --nickname "{}"'.format(constants.CA_INSTANCE_NAME,
                                                                    file_name, user_id)

    certutil_cmd = 'certutil -L -d  {} | grep \"{}\"'.format(BASE_DB_DIR.format(
        constants.CA_INSTANCE_NAME), user_id)

    del_cert = 'pki-server instance-externalcert-del -i {} --nickname "{}" ' \
               '--token NHSM6000'.format(constants.CA_INSTANCE_NAME, user_id)

    add_cmd_output = ansible_module.expect(command=certificate_add_cmd,
                                           responses={
                                               "Enter password for NHSM6000: ": "SECret.579"})
    for result in add_cmd_output.values():
        if result['rc'] == 0:
            assert "Certificate imported for instance " + constants.CA_INSTANCE_NAME in \
                   result['stdout']

            certImported = ansible_module.command(certutil_cmd)
            for res in certImported.values():
                if res['rc'] == 0:
                    assert user_id in res['stdout']
                else:
                    pytest.xfail("Failed to run pki-server instance-external-cert-add "
                                 "command with NHSM6000 token")
        else:
            assert "certutil: could not find the slot NHSM6000: SEC_ERROR_NO_TOKEN: The security " \
                   "card or token does not exist, needs to be initialized, or has " \
                   "been removed." in result['stdout']
    ansible_module.command('rm -rf {}'.format(file_name))
    cmd_output = ansible_module.expect(command=del_cert,
                                       responses={
                                           "Enter password for NHSM6000: ": "SECret.579"})
    for result in cmd_output.values():
        if result['rc'] == 0:
            assert "Certificate removed from " \
                   "instance {}.".format(constants.CA_INSTANCE_NAME) in result['stdout']
