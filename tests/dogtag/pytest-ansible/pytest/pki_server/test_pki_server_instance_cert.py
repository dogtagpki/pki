"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI-SERVER CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki securitydomain commands needs to be tested:
#   pki-server instance-cert-export --help
#   pki-server instance-cert-export
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

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
TOPOLOGY = constants.CA_INSTANCE_NAME.split("-")[-2]

if TOPOLOGY == '01':
    ca_instance_name = 'pki-tomcat'
    topology_name = 'topology-01-CA'
else:
    ca_instance_name = constants.CA_INSTANCE_NAME
    topology_name = constants.CA_INSTANCE_NAME


def test_pki_server_instance_cert_command(ansible_module):
    """
    :id: 2cab6061-fc45-4403-977b-0c4f619c5ffc
    :Title: Test pki-server instance-cert command
    :Description: Test pki-server instance-cert command
    :Requirement: Pki Server Instance
    :CaseComponent: \-
    :Steps:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :ExpectedResults: Verify whether pki-server instance-cert --help command shows
        the instance-cert-export.
    """
    instance_cert = 'pki-server instance-cert'
    cmd_output = ansible_module.command(instance_cert)
    for result in cmd_output.values():
        if result['rc'] == 0:
            assert "instance-cert-export          Export system certificates " in result['stdout']
        else:
            pytest.skip("Failed to run pki-server instance-cert command")


def test_pki_server_instance_cert_command_with_help(ansible_module):
    """
    :id: d8f26419-1d25-4ba3-8887-2bd477fcca09
    :Title: RHCS-TC Test pki-server instance-cert --help command. BZ: 1339263
    :Description: RHCS-TC Test pki-server instance-cert --help command. BZ: 1339263
    :Requirement: Pki Server Instance
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server instance-cert --help command shows the instance-cert-export.
    """
    instance_cert_help = 'pki-server instance-cert --help'
    cmd_output = ansible_module.command(instance_cert_help)
    for result in cmd_output.values():
        if result['rc'] == 0:
            assert "instance-cert-export          Export system certificates " in result['stdout']
        else:
            pytest.skip("Failed to run pki-server instance-cert --help command")


def test_pki_server_instance_cert_export_command_with_help(ansible_module):
    """
    :id: 234eb46c-66bd-46d7-8895-795d33d8ea5e
    :Title: Test pki-server instance-cert-export --help command, BZ:1339263
    :Description: Test pki-server instance-cert-export --help command, BZ:1339263
    :Requirement: Pki Server Instance
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server instance-cert-export --help command shows the
            instance-cert-export.
    """
    instance_cert_export = 'pki-server instance-cert-export --help'
    cmd_output = ansible_module.command(instance_cert_export)
    for result in cmd_output.values():
        if result['rc'] == 0:
            assert "Usage: pki-server instance-cert-export [OPTIONS] [nicknames...]" in result[
                'stdout']
            assert "-i, --instance <instance ID>       Instance ID (default: pki-tomcat)." in \
                   result['stdout']
            assert "--pkcs12-file <path>           Output file to store the exported certificate " \
                   "and key in PKCS #12 format." in result['stdout']
            assert "--pkcs12-password <password>   Password for the PKCS #12 file." in result[
                'stdout']
            assert "--pkcs12-password-file <path>  Input file containing the password for the " \
                   "PKCS #12 file." in result['stdout']
            assert "--append                       Append into an existing PKCS #12 file." \
                   in result['stdout']
            assert "--no-trust-flags               Do not include trust flags" in result['stdout']
            assert "--no-key                       Do not include private key" in result['stdout']
            assert "--no-chain                     Do not include certificate chain" in \
                   result['stdout']
            assert "-v, --verbose                      Run in verbose mode." in result['stdout']
            assert "--debug                        Run in debug mode." in result['stdout']
            assert "--help                         Show help message." in result['stdout']
        else:  # If fail display error and exit
            pytest.skip("Failed to run pki-server instance-cert-export --help command")


@pytest.mark.parametrize('systems', ['ca', 'kra'])  # TODO remove after build , 'ocsp', 'tks', 'tps'])
def test_pki_server_instance_cert_export_command(ansible_module, systems):
    """
    :id: c6770e1a-8efc-41e5-b4ce-cf68ffbb874b
    :Title: Test pki-server instance-cert-export command.
    :Description: Test pki-server instance-cert-export command.
    :Requirement: Pki Server Instance
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server instance-cert-export command shows the export
           certificate in p12 format.
    """
    if TOPOLOGY == '01':
        instance = ca_instance_name
    else:
        instance = eval("constants.{}_INSTANCE_NAME".format(systems.upper()))
    p12_file = '/tmp/{}_admin_cert.p12'.format(systems)
    instance_cert_export = 'pki-server instance-cert-export -i {} --pkcs12-file ' \
                           '{} --pkcs12-password {}'.format(instance, p12_file,
                                                            constants.CLIENT_PKCS12_PASSWORD)

    cmd_output = ansible_module.command(instance_cert_export)
    for result in cmd_output.values():
        if result['rc'] == 0:
            assert "Export complete" in result['stdout']
            log.info("Successfully run: {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run: {}".format(" ".join(result['cmd'])))
            pytest.skip()


@pytest.mark.parametrize('systems', ['ca', 'kra'])  # TODO remove after build, 'ocsp', 'tks', 'tps'])
def test_pki_server_instance_cert_export_command_with_password_file(ansible_module, systems):
    """
    :id: cbdd77a4-b4f7-497c-b247-3ae8b9f5f8a2
    :Title: RHCS-TC Test pki-server instance-cert-export command with wrong password file.
    :Description: RHCS-TC Test pki-server instance-cert-export command with wrong password file.
    :Requirement: Pki Server Instance
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server instance-cert-export command shows the export
        certificate in p12 format.
    """
    password = constants.CLIENT_DIR_PASSWORD
    password_file = "/tmp/password.txt"
    if TOPOLOGY == '01':
        instance = ca_instance_name
    else:
        instance = eval("constants.{}_INSTANCE_NAME".format(systems.upper()))

    ansible_module.shell('echo "{}" > {}'.format(password, password_file))

    instance_cert_export = 'pki-server instance-cert-export -i {} --pkcs12-file /tmp/{}.p12 ' \
                           '--pkcs12-password-file {} --no-chain --no-key ' \
                           '--no-trust-flags'.format(instance, systems, password_file)

    cmd_output = ansible_module.command(instance_cert_export)
    for result in cmd_output.values():
        if result['rc'] == 0:
            assert "Export complete" in result['stdout']
            log.info("Successfully run: {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run: {}".format(" ".join(result['cmd'])))
            pytest.skip()


def test_pki_server_instance_cert_export_command_when_instance_does_not_exists(ansible_module):
    """
    :id: ac9c6e53-46a0-4fa4-9d1b-72e762117e25
    :Title: Test pki-server instance-cert-export command when instance does not exists.
    :Description: test pki-server instance-cert-export command, This test also verifies
                  bugzilla id : 1348433
    :CaseComponent: \-
    :Requirement: Pki Server Instance
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server instance-cert-export command failed to the export
        certificate in p12 format and throws error.
    """
    subsystems = "ABcCA"
    password = constants.CLIENT_DIR_PASSWORD
    password_file = "/tmp/password.txt"
    ansible_module.shell('echo "{}" > {}'.format(password, password_file))
    instance_cert_export = 'pki-server instance-cert-export -i {} --pkcs12-file /tmp/{}.p12 ' \
                           '--pkcs12-password-file {} --no-chain --no-key ' \
                           '--no-trust-flags'.format(subsystems, subsystems, password_file)

    cmd_output = ansible_module.command(instance_cert_export)
    for result in cmd_output.values():
        if result['rc'] >= 1:
            assert "ERROR: Invalid instance %s." % subsystems in result['stderr']
            log.info("Successfully run: {}".format(" ".join(result['cmd'])))
        else:
            assert "Export complete" in result['stdout']
            log.error("Failed to run: {}".format(" ".join(result['cmd'])))
            pytest.skip()


@pytest.mark.parametrize('systems', ['ca', 'kra'])  # TODO remove after build  , 'ocsp', 'tks', 'tps'])
def test_pki_server_instance_cert_export_command_when_instance_is_stopped(ansible_module, systems):
    """
    :id: 5c7e9354-8262-480a-bab9-695bb114bf66
    :Title: RHCS-TC Test pki-server instance-cert-export command when instance is stopped.
    :Requirement: Pki Server Instance
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server instance-cert-export command shows the export certificate
        in p12 format when instance is stopped.
    """
    password = constants.CLIENT_DIR_PASSWORD
    password_file = "/tmp/password.txt"
    if TOPOLOGY == '01':
        instance = ca_instance_name
    else:
        instance = eval("constants.{}_INSTANCE_NAME".format(systems.upper()))
    stop_instance_cmd = 'pki-server instance-stop {}'.format(instance)
    start_instance_cmd = 'pki-server instance-start {}'.format(instance)

    cert_export_command = 'pki-server instance-cert-export -i {} --pkcs12-file /tmp/{}.p12 ' \
                          '--pkcs12-password-file /tmp/password.txt --no-chain --no-key ' \
                          '--no-trust-flags'.format(instance, systems)
    ansible_module.shell('echo "{}" > {}'.format(password, password_file))
    ansible_module.command(stop_instance_cmd)

    cmd_output = ansible_module.command(cert_export_command)

    ansible_module.command(start_instance_cmd)
    for result in cmd_output.values():
        if result['rc'] == 0:
            assert "Export complete" in result['stdout']
            log.info("Successfully run: {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run: {}".format(" ".join(result['cmd'])))
            pytest.skip()


def test_pki_server_instance_cert_export_command_client_dir_invalid_path(ansible_module):
    """
    :id: 3ee08cea-2801-4e69-a154-c1f057589980
    :Title: Test pki-server instance-cert-export with invalid client directory path BZ: 1348433
    :Description:
    :Requirement: Pki Server Instance
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server instance-cert-export command shows the
        FileNotFoundException: file not found and return code == 1 .
    """
    password = constants.CLIENT_DIR_PASSWORD
    password_file = "/tmp/password.txt"

    ansible_module.shell('echo "{}" > {}'.format(password, password_file))

    cert_export_command = 'pki-server instance-cert-export -i {} --pkcs12-file /sdf/{}.p12 ' \
                          '--pkcs12-password-file /tmp/password.txt --no-chain --no-key ' \
                          '--no-trust-flags'.format(constants.CA_INSTANCE_NAME,
                                                    constants.CA_INSTANCE_NAME)
    cmd_output = ansible_module.command(cert_export_command)
    for result in cmd_output.values():
        if result['rc'] == 0:
            assert "Export complete" in result['stdout']
            log.error("Failed to run: {}".format(" ".join(result['cmd'])))
            pytest.skip()
        else:
            is_file = ansible_module.stat(path='/sdf/{}.p12'.format(constants.CA_INSTANCE_NAME))
            for res in is_file.values():
                assert res['stat']['exists'] is False
                log.info("Successfully run: {}".format(" ".join(result['cmd'])))


@pytest.mark.skipif(TOPOLOGY='01')
def test_pki_server_instance_cert_export_command_with_append(ansible_module):
    """
    :id: 5ef57c14-364a-467d-84e8-b60c22642f8c
    :Title: Test pki-server instance-cert-export, append to existing certificate.
    :Description: Test pki-server instance-cert-export, append to existing certificate
    :Requirement: Pki Server Instance
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :ExpectedResults:
        1. Verify whether pki-server instance-cert-export command shows the export certificate
        in p12 format and append option append the certificates to existing file.
    """
    # Store all subsystems in list
    subsystems = ['kra']  # TODO remove after build , 'ocsp', 'tks', 'tps']
    password = constants.CLIENT_DIR_PASSWORD
    password_file = "/tmp/password.txt"
    ansible_module.shell('echo "{}" > {}'.format(password, password_file))
    pkcs12_file = "/tmp/ca_pkcs12_cert.p12".format()

    cert_export = 'pki-server instance-cert-export -i {} --pkcs12-file {} ' \
                  '--pkcs12-password-file {}'

    ca_cert = ansible_module.command(cert_export.format(ca_instance_name,
                                                        pkcs12_file, password_file))

    for result in ca_cert.values():
        if result['rc'] == 0:
            assert "Export complete" in result['stdout']
            log.info("Export complete")
            log.info("Successfully run: {}".format(" ".join(result['cmd'])))
        else:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()

    cert_export_command = 'pki-server instance-cert-export "auditSigningCert cert-{} {}" -i {} ' \
                          '--pkcs12-file {} --pkcs12-password-file {} --no-chain --no-key ' \
                          '--no-trust-flags --append'
    for system in subsystems:
        if TOPOLOGY == '01':
            instance = ca_instance_name
        else:
            instance = eval('constants.{}_INSTANCE_NAME'.format(system.upper()))

        cmd_output = ansible_module.command(cert_export_command.format(instance, system.upper(),
                                                                       instance, pkcs12_file, password_file))
        for result in cmd_output.values():
            if result['rc'] == 0:
                assert 'Export complete' in result['stdout']
                log.info("Successfully run: {}".format(" ".join(result['cmd'])))
            else:
                log.error("Failed to run : {}".format(" ".join(result['cmd'])))
                pytest.skip()
    is_file = ansible_module.stat(path=pkcs12_file)
    for res in is_file.values():
        if res['stat']['exists']:
            ansible_module.command('pki -d /tmp/n -c {} client-init '
                                   '--force'.format(constants.CLIENT_PKCS12_PASSWORD))
            command = ansible_module.command('pki -d /tmp/n -c {} client-cert-import '
                                             '--pkcs12 {} --pkcs12-password-file '
                                             '{}'.format(constants.CLIENT_PKCS12_PASSWORD,
                                                         pkcs12_file, password_file))
            a = ansible_module.command('certutil -L -d /tmp/n')
            ansible_module.command('rm -rf /tmp/n')
            for result in a.values():
                if result['rc'] == 0:
                    for system in subsystems:
                        if TOPOLOGY == '01':
                            instance = ca_instance_name
                        else:
                            instance = eval('constants.{}_INSTANCE_NAME'.format(system.upper()))
                        assert "auditSigningCert cert-{} {}".format(instance, system.upper()) in result['stdout']
                        log.info("Successfully found: {}".format("auditSigningCert cert-{} "
                                                                 "{}".format(instance, system.upper())))
                else:
                    log.error("Failed to run : {}".format(" ".join(result['cmd'])))
                    pytest.skip()
        else:
            log.error("Failed to run : {}".format(res['cmd']))
            pytest.skip()


def test_pki_server_instance_cert_export_command_with_invalid_password(ansible_module):
    """
    :id: 75c8e6fc-bbed-4f62-8971-a261493c6516
    :Title: Test pki-server instance-cert-export with invalid password, BZ:1348433
    :Description: Test pki-server instance-cert-export with invalid password, BZ: 1348433
    :Requirement: Pki Server Instance
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server instance-cert-export command shows the error message
           "ERROR: option --pkcs12-password requires argument".
    """

    instance_cert_export = 'pki-server instance-cert-export -i {} --pkcs12-file /tmp/cert.p12 ' \
                           '--pkcs12-password {}'

    cmd_output = ansible_module.command(instance_cert_export.format(ca_instance_name, "SECRET123"))
    for result in cmd_output.values():
        if result['rc'] == 0:
            assert 'Export complete' in result['stdout']
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
        else:
            assert "ERROR: option --pkcs12-password requires argument" in result['stdout']
            assert "Usage: pki-server instance-cert-export [OPTIONS] [nicknames...]" in \
                   result['stdout']
            assert "-i, --instance <instance ID>       Instance ID (default: pki-tomcat)." in \
                   result['stdout']
            assert "--pkcs12-file <path>           Output file to store the exported " \
                   "certificate and key in PKCS #12 format." in result['stdout']
            assert "--pkcs12-password <password>   Password for the PKCS #12 file." in \
                   result['stdout']
            assert "--pkcs12-password-file <path>  Input file containing the password for " \
                   "the PKCS #12 file." in result['stdout']
            assert "--append                       Append into an existing PKCS #12 file." in \
                   result['stdout']
            assert "--no-trust-flags               Do not include trust flags" in \
                   result['stdout']
            assert "--no-key                       Do not include private key" in \
                   result['stdout']
            assert "--no-chain                     Do not include certificate chain" in \
                   result['stdout']
            assert "-v, --verbose                      Run in verbose mode." in \
                   result['stdout']
            assert "--debug                        Run in debug mode." in result['stdout']
            assert "--help                         Show help message." in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))
