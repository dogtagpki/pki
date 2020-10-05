"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI KRA-AUDIT CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki kra-audit cli commands needs to be tested:
#   pki kra-audit-file-retrieve
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Pritam Singh <prisingh@redhat.com>
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

import logging

from pki.testlib.common.certlib import sys, os
from pki.testlib.common.utils import UserOperations
import pytest
import re

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

userop = UserOperations(nssdb=constants.NSSDB)
log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)


@pytest.mark.parametrize('args', ['--help', 'asdf', ''])
def test_pki_kra_audit_file_retrieve_help(ansible_module, args):
    """
    :Title: Test pki kra-audit-file-retrieve  --help command.
    :Description: test pki kra-audit-file-retrieve --help command
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c
           SECret.123 -n "PKI KRA Administrator for Example.Org"
           kra-audit-file-retrieve --help
        2. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c
        SECret.123 -n "PKI KRA Administrator for Example.Org"
        kra-audit-file-retrieve asdf
        3. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c
        SECret.123 -n "PKI KRA Administrator for Example.Org"
        kra-audit-file-retrieve
    :Expected results:
        1. It should return help message.
        2. It should return exception
        3. It should return audit configuration
    """
    cmd_out = ansible_module.pki(cli="kra-audit-file-retrieve",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='{}'.format(args))
    for result in cmd_out.values():
        if args == '--help':
            assert result['rc'] == 0
            assert "usage: kra-audit-file-retrieve <filename> [OPTIONS...]" in result['stdout']
            assert "--help            Show help message." in result['stdout']
            assert "--output <path>   Output file." in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        elif args == 'asdf':
            assert result['rc'] >= 1
            assert 'ForbiddenException: Authorization Error' in result['stderr']
            log.info("Successfully run : '{}'".format(result['cmd']))
        elif args == '':
            assert result['rc'] >= 1
            assert "ERROR: Missing audit file name." in result['stderr']
            log.info("Successfully ran : '{}'".format(result['cmd']))


def test_pki_kra_audit_file_retrieve_for_non_existing_certificate_nickname(ansible_module):
    """
    :Title: pki kra-audit-file-retrieve for non-existing certificate nickname
    :Description: Issue pki kra-audit-file-retrieve for non exiting certificate nickname should fail
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c SECret.123
           -n "Nonexistingcertificate" kra-audit-file-retrieve
    :Expected results:
        1. It should return a certificate not found exception

    """
    cmd_out = ansible_module.pki(cli="kra-audit-file-retrieve",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='{}'.format("NonExistingCertificate"))
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert 'RuntimeException: org.mozilla.jss.crypto.ObjectNotFoundException: ' \
                   'Certificate not found: NonExistingCertificate' in result['stderr']
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


def test_pki_kra_audit_file_retrieve_as_anonymous_user(ansible_module):
    """
    :Title: pki kra-audit-file-retrieve as anonymous user
    :Description: Execute pki kra-audit-file-retrieve as anonymous user should fail
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 kra-audit-file-retrieve
    :Expected results:
        2. It should return unauthorised Exception

    """
    command = 'pki -d {} -c {} -h {} -P http -p {} kra-audit-file-retrieve kra_cert-kra_audit'.format(
        constants.NSSDB,
        constants.CLIENT_DIR_PASSWORD,
        constants.MASTER_HOSTNAME,
        constants.KRA_HTTP_PORT)
    cmd_out = ansible_module.command(command)
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert 'PKIException: Unauthorized' in result['stderr']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


def test_pki_kra_audit_file_retrieve_with_audit_file_name(ansible_module):
    """
    :Title: pki kra-audit-file-retrieve with audit file name
    :Description: Issue pki kra-audit-file-retrieve with audit file name
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c SECret.123
           -n "PKI KRA Administrator for Example.Org" kra-audit-file-retrieve kra_cert-kra_audit
    :Expected results:
        1. It should retrieve a audit config
    """
    path = '/root/kra_cert-kra_audit'
    cmd_out = ansible_module.pki(cli="kra-audit-file-retrieve",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format("KRA_AuditV"),
                                 extra_args='{}'.format("kra_cert-kra_audit"))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert result['rc'] == 0
            log.info("Successfully ran : {}".format(result['cmd']))
            is_file = ansible_module.stat(path=path)
            for r1 in is_file.values():
                assert r1['stat']['exists']
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


def test_pki_kra_audit_file_retrieve_with_output_option(ansible_module):
    """
    :Title: pki kra-audit-file-retrieve with output option
    :Description: Issue pki kra-audit-file-retrieve with output option and
                  verify output is generated
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c SECret.123
           -n "PKI KRA Administrator for Example.Org" kra-audit-file-retrieve kra_cert-kra_audit
                                                              --output /tmp/auditconf
    :Expected results:
        1. It should generate a output with specific name

    """
    # Fetch file name
    cmd_out = ansible_module.pki(cli="kra-audit-file-find",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format('KRA_AuditV'))
    for result in cmd_out.values():
        if result['rc'] == 0:
            raw_file_name = re.findall('File name: [\w].*', result['stdout'])
            file_name = raw_file_name[0].split(":")[1].strip()
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    path = '/tmp/auditconf'
    cmd_out = ansible_module.pki(cli="kra-audit-file-retrieve",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format("KRA_AuditV"),
                                 extra_args='{} --output {}'.format(file_name, path))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert result['rc'] == 0
            log.info('Successfully ran : {}'.format(result['cmd']))
            is_file = ansible_module.stat(path=path)
            for r1 in is_file.values():
                assert r1['stat']['exists']
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
    ansible_module.command('rm -rf {}'.format(path))


@pytest.mark.parametrize("valid_user_cert", ["KRA_AdminV", "KRA_AgentV", "KRA_AuditV"])
def test_pki_kra_audit_file_retrieve_with_valid_user_cert(valid_user_cert, ansible_module):
    """
    :Title: pki kra-audit-file-retrieve with different valid user's cert
    :Description: Executing pki kra-audit-file-retrieve using valid user cert should pass
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AdminV" kra-audit-file-retrieve kra_cert-kra_audit
        2. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AgentV" kra-audit-file-retrieve kra_cert-kra_audit
        3. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AuditV" kra-audit-file-retrieve kra_cert-kra_audit
    :Expected results:
        1. It should retrieve config for KRA_auditV cert

    """
    cmd_out = ansible_module.pki(cli="kra-audit-file-retrieve",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(valid_user_cert),
                                 extra_args='{}'.format("kra_cert-kra_audit"))
    for result in cmd_out.values():
        if valid_user_cert in ['KRA_AdminV', 'KRA_AgentV']:
            assert result['rc'] >= 1
            assert 'ForbiddenException: Authorization Error' in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
        elif valid_user_cert == 'KRA_AuditV':
            assert result['rc'] == 0
            log.info('Successfully ran : {}'.format(result['cmd']))


@pytest.mark.parametrize("revoked_user_cert", ["KRA_AdminR", "KRA_AgentR", "KRA_AuditR"])
def test_pki_kra_audit_file_retrieve_with_revoked_user_cert(revoked_user_cert, ansible_module):
    """
    :Title: pki kra-audit-file-retrieve with different revoked user's cert
    :Description: Executing pki kra-audit-file-retrieve using revoked user cert
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AdminR" kra-audit-file-retrieve kra_cert-kra_audit
        2. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AgentR" kra-audit-file-retrieve kra_cert-kra_audit
        3. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AuditR" kra-audit-file-retrieve kra_cert-kra_audit
    :Expected results:
        1. It should throw an Exception.

    """
    cmd_out = ansible_module.pki(cli="kra-audit-file-retrieve",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(revoked_user_cert),
                                 extra_args='{}'.format("kra_cert-kra_audit"))
    for result in cmd_out.values():
        if result['rc'] > 0:
            assert 'SEVERE: FATAL: SSL alert received: CERTIFICATE_REVOKED\nIOException: ' \
                   'SocketException cannot read on socket: Error reading from socket: ' \
                   '(-12270) SSL peer rejected your certificate as revoked.' in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail('Failed to run : {}'.format(result['cmd']))


@pytest.mark.parametrize("expired_user_cert", ["KRA_AdminE", "KRA_AgentE", "KRA_AuditE"])
def test_pki_kra_audit_file_retrieve_with_expired_user_cert(expired_user_cert, ansible_module):
    """
    :Title: pki kra-audit-file-retrieve with different user's expired cert
    :Description: Executing pki kra-audit-file-retrieve using expired user cert
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AdminE" kra-audit-file-retrieve kra_cert-kra_audit
        2. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AgentE" kra-audit-file-retrieve kra_cert-kra_audit
        3. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AuditE" kra-audit-file-retrieve kra_cert-kra_audit
    :Expected results:
        1. It should return an Certificate Unknown Exception.

    """
    cmd_out = ansible_module.pki(cli="kra-audit-file-retrieve",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(expired_user_cert),
                                 extra_args='{}'.format("kra_cert-kra_audit"))
    for result in cmd_out.values():
        if result['rc'] == 0:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail('Failed to run : {}'.format(result['cmd']))
        elif result['rc'] >= 1:
            assert "SEVERE: FATAL: SSL alert received: CERTIFICATE_EXPIRED\nIOException: " \
                   "SocketException cannot read on socket: Error reading from socket: " \
                   "(-12269) SSL peer rejected your certificate as expired." in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))


def test_pki_kra_audit_file_retrieve_with_invalid_user(ansible_module):
    """
    :Title: pki kra-audit-file-retrieve with invalid user's cert
    :Description: Issue pki kra-audit-file-retrieve with invalid user
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c SECret.123
           -u pki_user -w Secret123 kra-audit-file-retrieve kra_cert-kra_audit
    :Expected results:
        1. It should return an Unauthorised Exception.

    """
    command_out = ansible_module.pki(cli="kra-audit-file-retrieve",
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.KRA_HTTP_PORT,
                                     authType='basicAuth',
                                     hostname=constants.MASTER_HOSTNAME,
                                     username='"{}"'.format("pki_user"),
                                     userpassword='"{}"'.format("Secret123"),
                                     extra_args='{} --output /tmp/audit'.format("kra_cert-kra_audit"))
    for result in command_out.values():
        if result['rc'] >= 1:
            assert 'PKIException: Unauthorized' in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


def test_pki_kra_audit_file_retrieve_with_normal_user_cert(ansible_module):
    """
    :Title: pki kra-audit-file_retrieve with normal user cert
    :Description: Issue pki kra-audit-file-retrieve with normal user cert should fail
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Add User
        2. Generate User Cert
        3. Add Cert to User
        4. Add User cert in database
        5. Show audit using the same user cert
    :Expected results:
        1. It should return an Forbidden Exception.
    """
    user = 'testUserCert2'
    fullName = 'testUserCert2'
    subject = "UID={},CN={}".format(user, fullName)
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName, subsystem='kra')
    cert_id = userop.process_certificate_request(ansible_module,
                                                 subject=subject,
                                                 request_type='pkcs10',
                                                 algo='rsa',
                                                 keysize='2048',
                                                 profile='caUserCert')
    ansible_module.pki(cli='kra-user-cert-add',
                       nssdb=constants.NSSDB,
                       dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                       port=constants.KRA_HTTP_PORT,
                       hostname=constants.MASTER_HOSTNAME,
                       certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                       extra_args='{} --serial {}'.format(user, cert_id))

    ansible_module.pki(cli='client-cert-import',
                       nssdb=constants.NSSDB,
                       dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                       port=constants.CA_HTTP_PORT,
                       hostname=constants.MASTER_HOSTNAME,
                       extra_args='{} --serial {}'.format(user, cert_id))

    cmd_out = ansible_module.pki(cli="kra-audit-file-retrieve",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(user),
                                 extra_args='{}'.format("kra_cert-kra_audit"))
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert "PKIException: Unauthorized" in result['stderr']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Remove the cert from nssdb
    userop.remove_client_cert(ansible_module, user, subsystem='ca')

    # Remove the user
    userop.remove_user(ansible_module, user, subsystem='kra')
