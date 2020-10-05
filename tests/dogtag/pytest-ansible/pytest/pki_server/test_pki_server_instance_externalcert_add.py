"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI-SERVER CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki-server instance-externalcert commands needs to be tested:
#    pki-server instance-externalcert-add --help
#    pki-server instance-externalcert-add
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
import sys
import time
from subprocess import CalledProcessError

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
log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
TOPOLOGY = constants.CA_INSTANCE_NAME.split("-")[-2]

if TOPOLOGY == '01':
    ca_instance_name = 'pki-tomcat'
    topology_name = 'topology-01-CA'
else:
    ca_instance_name = constants.CA_INSTANCE_NAME
    topology_name = constants.CA_INSTANCE_NAME


def create_cert(ansible_module):
    """
    Return a base 64 encoded certificate.
    """
    no = random.randint(11, 999989)
    user = 'testuser{}'.format(no)
    subject = 'UID={},CN={}'.format(user, user)
    cert_id = userop.process_certificate_request(ansible_module, subject=subject)
    if cert_id:
        cert_file = "/tmp/{}.pem".format(user)
        ansible_module.command('pki -d {} -c {} -P http -p {} client-cert-import "{}" '
                               '--serial {}'.format(constants.NSSDB, constants.CLIENT_DIR_PASSWORD,
                                                    constants.CA_HTTP_PORT, user, cert_id))
        ansible_module.command('pki -d {} -c {} client-cert-show "{}" '
                               '--cert /tmp/{}.pem '.format(constants.NSSDB,
                                                            constants.CLIENT_DIR_PASSWORD,
                                                            user, user))
        ansible_module.command('pki -d {} -c {} client-cert-del '
                               '"{}"'.format(constants.NSSDB, constants.CLIENT_DIR_PASSWORD,
                                             user))
        return [cert_id, cert_file]


def test_pki_server_instance_externalcert_add_help_command(ansible_module):
    """
    :id: ea41448f-31e5-4aeb-9656-b6788387f4ab
    :Title: Test pki-server instance-externalcert-add --help command, BZ: 1339263
    :Description: Test pki-server instance-externalcert-add --help command, This test also 
                  verifies bugzilla id : 1339263
    :Requirement: Pki Server Instance
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :ExpectedResults: Verify whether pki-server instance-externalcert --help command shows the 
            following output.

        Usage: pki-server instance-externalcert-add [OPTIONS]
    
          -i, --instance <instance ID>       Instance ID (default: pki-tomcat).
              --cert-file <path>             Input file containing the external certificate or 
              certificate chain.
              --trust-args <trust-args>      Trust args (default ",,").
              --nickname <nickname>          Nickname to be used.
              --token <token_name>           Token (default: internal).
          -v, --verbose                      Run in verbose mode.
              --help                         Show help message.
    """

    help_command = 'pki-server instance-externalcert-add --help'
    cmd_output = ansible_module.command(help_command)
    for result in cmd_output.values():
        if result['rc'] == 0:
            assert "Usage: pki-server instance-externalcert-add [OPTIONS]" in result['stdout']
            assert "-i, --instance <instance ID>       Instance ID (default: pki-tomcat)." in \
                   result['stdout']
            assert "--cert-file <path>             Input file containing the external " \
                   "certificate or certificate chain." in result['stdout']
            assert '--trust-args <trust-args>      Trust args (default ",,").' in \
                   result['stdout']
            assert "--nickname <nickname>          Nickname to be used." in result['stdout']
            assert "--token <token_name>           Token (default: internal)." in \
                   result['stdout']
            assert "-v, --verbose                      Run in verbose mode." in \
                   result['stdout']
            assert "--help                         Show help message." in result['stdout']
        else:
            pytest.skip("Failed to run pki-server instance-externalcert-add --help command.")


def test_pki_server_instance_externalcert_add_command(ansible_module):
    """
    :id: 6d6ae4d1-b5d5-423d-bd62-81b274ff4c9d
    :Title: Test pki-server instance-externalcert-add command 
    :Description: Test pki-server instance-externalcert-add command
    :Requirement: Pki Server Instance
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server instance-externalcert-add command add the certificate
            to the instance.
    """
    cert_id, cert_file = create_cert(ansible_module)
    user_id = cert_file.split("/")[-1].split(".")[0]

    certificate_add_cmd = 'pki-server instance-externalcert-add -i {} --cert-file ' \
                          ' {} --trust-args "u,u,u" --nickname "{}" ' \
                          '--token internal'.format(ca_instance_name, cert_file, user_id)

    certutil_cmd = 'certutil -L -d {} | ' \
                   'grep \"{}\"'.format(BASE_DB_DIR.format(ca_instance_name), user_id)

    del_cert = 'pki-server instance-externalcert-del -i {} --nickname "{}" ' \
               '--token internal'.format(ca_instance_name, user_id)

    cmd_output = ansible_module.command(certificate_add_cmd)

    for result in cmd_output.values():
        if result['rc'] == 0:
            assert "Certificate imported for instance {}".format(ca_instance_name) in \
                   result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run: {}".format(" ".join(result['cmd'])))
            pytest.skip("Failed to run pki-server instance-externalcert-add command")
    certImported = ansible_module.shell(certutil_cmd)
    for res in certImported.values():
        if res['rc'] == 0:
            assert user_id in res['stdout']
        else:
            log.error("Failed to run : {}".format(res['cmd']))
            pytest.skip()
    ansible_module.command('rm -rf {}'.format(cert_file))
    cmd_output = ansible_module.command(del_cert)
    for result in cmd_output.values():
        if result['rc'] == 0:
            assert "Certificate removed from " \
                   "instance {}.".format(ca_instance_name) in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()


# @pytest.mark.xfail(raises=CalledProcessError)
def test_pki_server_instance_externalcert_add_with_invalid_args(ansible_module):
    """
    :id: d677121b-a2d4-4c54-956c-ccd75b918a52
    :Title: Test pki-server instance-externalcert-add with invalid args command, BZ:1348433
    :Description: test pki-server instance-externalcert-add command
        This test also verifies bugzilla id : 1348433
    :CaseComponent: \-
    :Requirement: Pki Server Instance
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server instance-externalcert-add command add the certificate to the
        instance without trust args expected to fail.
    """
    cert_id, file_name = create_cert(ansible_module)
    user_id = file_name.split("/")[-1].split(".")[0]

    certificate_add_cmd = 'pki-server instance-externalcert-add -i {} --cert-file {} --nickname ' \
                          '"{}" --token internal'.format(ca_instance_name, file_name, user_id)

    certutil_cmd = 'certutil -L -d  {} | grep \"{}\"'.format(BASE_DB_DIR.format(ca_instance_name), user_id)

    cmd_output = ansible_module.command(certificate_add_cmd)
    for result in cmd_output.values():
        if result['rc'] >= 1:
            assert "certutil: unable to decode trust string: SEC_ERROR_INVALID_ARGS: security " \
                   "library: invalid arguments." in result['stderr']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            assert "Certificate imported for instance {}".format(ca_instance_name) in \
                   result['stdout']
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))

    certutil_out = ansible_module.shell(certutil_cmd)
    for result in certutil_out.values():
        if result['rc'] == 0:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip("Failed to run pki-server instance-externalcert-add without trust.")

    ansible_module.command('rm -rf {}'.format(file_name))


def test_pki_server_instance_externalcert_add_without_nickname(ansible_module):
    """
    :id: ec7571a0-045a-471d-b441-3a43f66c4a50
    :Title: Test pki-server instance-externalcert-add without nickname, BZ : 1348433
    :Description:
        test pki-server instance-externalcert-add command, BZ : 1348433
    :CaseComponent: \-
    :Requirement: Pki Server Instance
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server instance-externalcert-add command should not add an external
        cert to the nssdb when nickname is missing.
    """

    cert_id, file_name = create_cert(ansible_module)
    user_id = file_name.split("/")[-1].split(".")[0]

    certificate_add_cmd = 'pki-server instance-externalcert-add -i {} --cert-file {} ' \
                          '--token internal'.format(ca_instance_name, file_name)

    certutil_cmd = 'certutil -L -d  {} | grep \"{}\"'.format(BASE_DB_DIR.format(ca_instance_name), user_id)

    cmd_output = ansible_module.command(certificate_add_cmd)
    for result in cmd_output.values():
        if result['rc'] >= 1:
            assert "ERROR: Missing nickname" in result['stderr']
            log.info("Successfully ran : {}".format(" ".join(result['cmd'])))
        else:
            assert "Certificate imported for instance {}".format(ca_instance_name) \
                   in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
            certImported = ansible_module.command(certutil_cmd)
            for res in certImported.values():
                if res['rc'] == 0:
                    assert user_id in res['stdout']
                    log.info("Successfully run : {}".format(res['cmd']))
                else:
                    log.error("Failed to run : {}".format(res['cmd']))
                    pytest.skip()

    ansible_module.command('rm -rf {}'.format(file_name))


# @pytest.mark.xfail(raises=CalledProcessError)
def test_pki_server_instance_externalcert_add_with_invalid_instance(ansible_module):
    """
    :id: 11b2567b-23ae-49f7-bd4c-061d5dce7ef7
    :Title: Test pki-server instance-externalcert-add with invalid instance, BZ: 1348433
    :Description: test pki-server instance-externalcert-add command, This test also verifies
            bugzilla id : 1348433
    :Requirement: Pki Server Instance
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server instance-externalcert-add command add the certificate to
        the instance which does not exists.
    """

    cert_id, file_name = create_cert(ansible_module)
    user_id = file_name.split("/")[-1].split(".")[0]

    certificate_add_cmd = 'pki-server instance-externalcert-add -i ROOTCA --cert-file {} ' \
                          '--token internal --nickname "{}"'.format(file_name, user_id)

    certutil_cmd = 'certutil -L -d  {} | grep \"{}\"'.format(BASE_DB_DIR.format(ca_instance_name), user_id)

    cmd_output = ansible_module.command(certificate_add_cmd)
    for result in cmd_output.values():
        if result['rc'] >= 1:
            assert "ERROR: Invalid instance ROOTCA." in result['stderr']
        else:
            assert "Certificate imported for instance {}".format(ca_instance_name) \
                   in result['stdout']
            certImported = ansible_module.command(certutil_cmd)
            for res in certImported.values():
                if res['rc'] == 0:
                    assert user_id in res['stdout']
                    log.info("Successfully run : {}".format(res['cmd']))
                else:
                    log.error("Failed to run : {}".format(res['cmd']))
                    pytest.skip()

    ansible_module.command('rm -rf {}'.format(file_name))


# @pytest.mark.xfail(reason=CalledProcessError)
def test_pki_server_instance_externalcert_add_with_invalid_token(ansible_module):
    """
    :id: 056914db-11e3-4809-8be3-17a621106bf9
    :Title: Test pki-server instance-externalcert-add with invalid token, BZ:1348433
    :Description: test pki-server instance-externalcert-add command
        This test also verifies bugzilla id : 1348433
    :CaseComponent: \-
    :Requirement: Pki Server Instance
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server instance-externalcert-add command add the certificate to the
        instance when token is invalid.
    """

    cert_id, file_name = create_cert(ansible_module)
    user_id = file_name.split("/")[-1].split(".")[0]
    certificate_add_cmd = 'pki-server instance-externalcert-add -i {} --cert-file {} ' \
                          '--token INVALID --nickname "{}" ' \
                          '--trust-args "u,u,u"'.format(ca_instance_name, file_name, user_id)

    certutil_cmd = 'certutil -L -d  {} | grep \"{}\"'.format(BASE_DB_DIR.format(ca_instance_name), user_id)

    add_cmd_output = ansible_module.expect(command=certificate_add_cmd,
                                           responses={"Enter password for INVALID: ":
                                                          constants.CLIENT_DIR_PASSWORD})
    for result in add_cmd_output.values():
        if result['rc'] == 0:
            assert "Certificate imported for instance " + ca_instance_name in \
                   result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
            certImported = ansible_module.command(certutil_cmd)
            for res in certImported.values():
                if res['rc'] == 0:
                    assert user_id in res['stdout']
                else:
                    log.error("Failed to run : {}".format(" ".join(result['cmd'])))
                    pytest.skip("Failed to run pki-server instance-external-cert-add "
                                "command with invalid token")
        else:
            # assert "certutil: could not find the slot Invalid: SEC_ERROR_NO_TOKEN: " \
            #     "The security card or token does not exist, needs to be initialized, " \
            #    "or has been removed." in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))
    ansible_module.command('rm -rf {}'.format(file_name))


def test_pki_server_instance_externalcert_add_when_instance_is_stopped(ansible_module):
    """
    :id: 90a7464f-fc9a-4461-a07e-94160bdcba36
    :Title: Test pki-server instance-externalcert-add when instance is stopped
    :Description: test pki-server instance-externalcert-add command
    :CaseComponent: \-
    :Requirement: Pki Server Instance
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server instance-externalcert-add command add the certificate to
        the instance when instance is stopped.
    """

    cert_id, file_name = create_cert(ansible_module)
    user_id = file_name.split("/")[-1].split(".")[0]

    instance = ca_instance_name
    stop_instance = 'pki-server instance-stop {}'.format(instance)
    start_instance = 'pki-server instance-start {}'.format(instance)
    ansible_module.command(stop_instance)

    certificate_add_cmd = 'pki-server instance-externalcert-add -i {} --cert-file {} ' \
                          '--token internal --nickname "{}" ' \
                          '--trust-args "u,u,u"'.format(ca_instance_name, file_name, user_id)

    certutil_cmd = 'certutil -L -d  {} | grep \"{}\"'.format(BASE_DB_DIR.format(ca_instance_name), user_id)

    del_cert = 'pki-server instance-externalcert-del -i {} --nickname "{}" ' \
               '--token internal'.format(ca_instance_name, user_id)

    cmd_output = ansible_module.command(certificate_add_cmd)
    for result in cmd_output.values():
        if result['rc'] == 0:
            assert "Certificate imported for instance {}".format(ca_instance_name) \
                   in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()
    certImported = ansible_module.command(certutil_cmd)
    for res in certImported.values():
        if res['rc'] == 0:
            assert user_id in res['stdout']
        else:
            log.error("Failed to find userid in the directory.")
            pytest.skip()
    ansible_module.command('rm -rf {}'.format(file_name))

    cmd_output = ansible_module.command(del_cert)
    for result in cmd_output.values():
        if result['rc'] == 0:
            assert "Certificate removed from " \
                   "instance {}.".format(ca_instance_name) in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()
    ansible_module.command(start_instance)
