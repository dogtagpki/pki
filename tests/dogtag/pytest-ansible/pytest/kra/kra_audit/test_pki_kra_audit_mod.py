"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI KRA-AUDIT CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki kra-audit cli commands needs to be tested:
#   pki kra-audit-mod
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
import time

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
def test_pki_kra_audit_mod_help(ansible_module, args):
    """
    :Title: Test pki kra-audit-mod  --help command.
    :Description: test pki kra-audit-mod --help command
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c
           SECret.123 -n "PKI KRA Administrator for Example.Org"
           kra-audit-mod --help
        2. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c
        SECret.123 -n "PKI KRA Administrator for Example.Org"
        kra-audit-mod asdf
        3. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c
        SECret.123 -n "PKI KRA Administrator for Example.Org"
        kra-audit-mod
    :Expected results:
        1. It should return help message.
        2. It should return exception
        3. It should return an error
    """
    cmd_out = ansible_module.pki(cli="kra-audit-mod",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='{}'.format(args))
    for result in cmd_out.values():
        if args == '--help':
            assert result['rc'] == 0
            assert "usage: kra-audit-mod [OPTIONS...]" in result['stdout']
            assert "--action <action>   Action: enable, disable." in result['stdout']
            assert "--help              Show help message." in result['stdout']
            assert "--input <file>      Input file containing audit configuration." in result['stdout']
            assert "--output <file>     Output file to store audit configuration." in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        elif args == 'asdf':
            assert result['rc'] >= 1
            assert 'ERROR: Too many arguments specified.' in result['stderr']
            log.info("Successfully run : '{}'".format(result['cmd']))
        elif args == '':
            assert result['rc'] >= 1
            assert "ERROR: Missing action or input file." in result['stderr']
            log.info("Successfully ran : '{}'".format(result['cmd']))


def test_pki_kra_audit_mod_modify_status_to_disabled(ansible_module):
    """
    :Title: pki kra-audit-show and modify the signed from false to true
    :Description: Issue pki kra-audit-show and modify the signed from false to true
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c SECret.123
            -n "PKI KRA Administrator for Example.Org" kra-audit-show
        2. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c SECret.123
               -n "PKI KRA Administrator for Example.Org" kra-audit-mod --action disable
    :Expected results:
        1. It should show the default audit conf
        2. It should disable the audit configuration

    """
    # Show the default audit configuration
    cmd_out = ansible_module.pki(cli="kra-audit-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Audit configuration" in result['stdout']
            assert "Status: Enabled" in result['stdout']
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Modify the status to disable
    cmd_out = ansible_module.pki(cli="kra-audit-mod",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='--action disable')
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Modified audit configuration" in result['stdout']
            assert "Status: Disabled" in result['stdout']
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


def test_pki_kra_audit_mod_modify_signed_from_true_to_false(ansible_module):
    """
    :Title: pki kra-audit-show and modify the signed from true to false
    :Description: Issue pki kra-audit-show and modify the signed from true to false
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c SECret.123
           -n "PKI KRA Administrator for Example.Org" kra-audit-show --output /tmp/auditconf
        2. update the configuration in auditconf
        3. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c SECret.123
           -n "PKI KRA Administrator for Example.Org" kra-audit-mod --input /tmp/auditconf
    :Expected results:
        1. It should export the audit configuration
        2. update the configuration
        3. It should update the changes of audit conf

    """
    # Show the audit conf
    cmd_out = ansible_module.pki(cli="kra-audit-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Audit configuration" in result['stdout']
            assert "Signed: true" in result['stdout']
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Export the audit conf
    path = '/tmp/auditconf'
    cmd_out = ansible_module.pki(cli="kra-audit-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='--output {}'.format(path))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Stored audit configuration into {}'.format(path) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
            is_file = ansible_module.stat(path=path)
            for r1 in is_file.values():
                assert r1['stat']['exists']
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Update the changes in conf file
    ansible_module.replace(dest=path, regexp='<Signed>true</Signed>', replace='<Signed>false</Signed>')
    ansible_module.replace(dest=path, regexp='disabled', replace='enabled')

    # Modify the changes
    cmd_out = ansible_module.pki(cli="kra-audit-mod",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='--input {}'.format(path))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Modified audit configuration" in result['stdout']
            assert "Signed: false" in result['stdout']
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Verify the changes in CS.cfg

    instance_path = 'cat /var/lib/pki/{}/conf/{}/CS.cfg'.format(constants.KRA_INSTANCE_NAME, 'kra')
    cmd = ansible_module.command(instance_path)
    for result in cmd.values():
        if result['rc'] == 0:
            assert "log.instance.SignedAudit.enable=false" in result['stdout']
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Rollback the changes in conf file
    ansible_module.replace(dest=path, regexp='<Signed>false</Signed>', replace='<Signed>true</Signed>')

    # Restore the changes as original
    cmd_out = ansible_module.pki(cli="kra-audit-mod",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='--input {}'.format(path))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Modified audit configuration" in result['stdout']
            assert "Signed: true" in result['stdout']
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    ansible_module.command('rm -rf {}'.format(path))


def test_pki_kra_audit_mod_modify_status_as_anonymous_user(ansible_module):
    """
    :Title: pki kra-audit-mod status to enable as anonymous user
    :Description: Execute pki kra-audit-mod status to enable as anonymous user should fail
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 kra-audit-mod --action enable
    :Expected results:
        2. It should return unauthorised Exception

    """
    command = 'pki -d {} -c {} -h {} -P http -p {} kra-audit-mod --action enable'.format(
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


def test_pki_kra_audit_mod_modify_the_signed_with_output_option(ansible_module):
    """
    :Title: pki kra-audit-show and modify the signed with output option
    :Description: Issue pki kra-audit-show and modify the signed with output option
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c SECret.123
           -n "PKI KRA Administrator for Example.Org" kra-audit-show --output /tmp/auditconf
        2. update the configuration in auditconf
        3. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c SECret.123
           -n "PKI KRA Administrator for Example.Org" kra-audit-mod --input /tmp/auditconf --output /tmp/mod_conf
    :Expected results:
        1. It should export the audit configuration
        2. update the configuration
        3. It should update the changes of audit conf with export the mod_conf

    """
    # Show the audit conf
    cmd_out = ansible_module.pki(cli="kra-audit-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Audit configuration" in result['stdout']
            assert "Signed: true" in result['stdout']
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Export the audit conf
    path = '/tmp/auditconf'
    cmd_out = ansible_module.pki(cli="kra-audit-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='--output {}'.format(path))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Stored audit configuration into {}'.format(path) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
            is_file = ansible_module.stat(path=path)
            for r1 in is_file.values():
                assert r1['stat']['exists']
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Update the changes in conf file
    ansible_module.replace(dest=path, regexp='<Signed>true</Signed>', replace='<Signed>false</Signed>')

    # Modify the changes
    mod_path = '/tmp/mod_conf'
    cmd_out = ansible_module.pki(cli="kra-audit-mod",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='--input {} --output {}'.format(path, mod_path))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Modified audit configuration" in result['stdout']
            log.info("Successfully ran : {}".format(result['cmd']))
            is_file = ansible_module.stat(path=mod_path)
            for r1 in is_file.values():
                assert r1['stat']['exists']
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    ansible_module.command('rm -rf {}'.format(path, mod_path))


@pytest.mark.parametrize("valid_user_cert", ["KRA_AdminV", "KRA_AgentV", "KRA_AuditV"])
def test_pki_kra_audit_mod_with_valid_user_cert(valid_user_cert, ansible_module):
    """
    :Title: pki kra-audit-mod with different valid user's cert
    :Description: Executing pki kra-audit-mod using valid user cert should pass
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AdminV" kra-audit-mod --action enable
        2. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AgentV" kra-audit-mod --action enable
        3. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AuditV" kra-audit-mod --action enable
    :Expected results:
        1. It should return Certificate for KRA_AdminV
        2. It should return forbidden exception of KRA_AgentV & KRA_AuditV

    """
    cmd_out = ansible_module.pki(cli="kra-audit-mod",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(valid_user_cert),
                                 extra_args='--action enable')
    for result in cmd_out.values():
        if valid_user_cert == 'KRA_AdminV':
            assert 'Modified audit configuration' in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        elif valid_user_cert in ['KRA_AgentV', 'KRA_AuditV']:
            assert result['rc'] >= 1
            assert "ForbiddenException: Authorization Error" in result['stderr']
            log.info("Successfully ran : {}".format(result['cmd']))


@pytest.mark.parametrize("revoked_user_cert", ["KRA_AdminR", "KRA_AgentR", "KRA_AuditR"])
def test_pki_kra_audit_mod_with_revoked_user_cert(revoked_user_cert, ansible_module):
    """
    :Title: pki kra-audit-mod with different revoked user's cert
    :Description: Executing pki kra-audit-mod using revoked user cert
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AdminR" kra-audit-mod --action enable
        2. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AgentR" kra-audit-mod --action enable
        3. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AuditR" kra-audit-mod --action enable
    :Expected results:
        1. It should throw an Exception.

    """
    cmd_out = ansible_module.pki(cli="kra-audit-mod",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(revoked_user_cert),
                                 extra_args='--action enable')
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
def test_pki_kra_audit_mod_with_expired_user_cert(expired_user_cert, ansible_module):
    """
    :Title: pki kra-audit-mod with different user's expired cert
    :Description: Executing pki kra-audit-mod using expired user cert
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AdminE" kra-audit-mod --action enable
        2. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AgentE" kra-audit-mod --action enable
        3. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AuditE" kra-audit-mod --action enable
    :Expected results:
        1. It should return an Certificate Unknown Exception.

    """
    cmd_out = ansible_module.pki(cli="kra-audit-mod",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(expired_user_cert),
                                 extra_args='--action enable')
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


def test_pki_kra_audit_mod_with_invalid_user(ansible_module):
    """
    :Title: pki kra-audit-mod with invalid user's cert
    :Description: Issue pki kra-audit-mod with invalid user
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c SECret.123
           -u pki_user -w Secret123 kra-audit-mod --action enable
    :Expected results:
        1. It should return an Unauthorised Exception.

    """
    command_out = ansible_module.pki(cli="kra-audit-mod",
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.KRA_HTTP_PORT,
                                     authType='basicAuth',
                                     hostname=constants.MASTER_HOSTNAME,
                                     username='"{}"'.format("pki_user"),
                                     userpassword='"{}"'.format("Secret123"),
                                     extra_args='--action enable')
    for result in command_out.values():
        if result['rc'] >= 1:
            assert 'PKIException: Unauthorized' in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


def test_pki_kra_audit_mod_with_normal_user_cert(ansible_module):
    """
    :Title: pki kra-audit-mod with normal user cert
    :Description: Issue pki kra-audit-mod with normal user cert should fail
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Add User
        2. Generate User Cert
        3. Add Cert to User
        4. Add User cert in database
        5. Modify audit using the same user cert
    :Expected results:
        1. It should return an Forbidden Exception.
    """
    user = 'testUserCert3'
    fullname = 'testUserCert3'
    subject = "UID={},CN={}".format(user, fullname)
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullname, subsystem='kra')
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

    cmd_out = ansible_module.pki(cli="kra-audit-mod",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(user),
                                 extra_args='--action enable')
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert "PKIException: Unauthorized" in result['stderr']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Remove the cert
    userop.remove_client_cert(ansible_module, user, subsystem='ca')

    # Remove the user
    userop.remove_user(ansible_module, user, subsystem='kra')


def test_pki_kra_audit_mod_modify_with_junk_input_file(ansible_module):
    """
    :Title: pki kra-audit-modify with junk input file
    :Description: Issue pki kra-audit-mod with junk input file
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c SECret.123
            -n "PKI KRA Administrator for Example.Org" kra-audit-mod --input test.txt
        2. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c SECret.123
               -n "PKI KRA Administrator for Example.Org" kra-audit-mod --input test.conf
    :Expected results:
        1. It should show the PKIException: Bad Request
    """
    path = '/tmp/junk_file.conf'
    ansible_module.shell('echo "random" > {}'.format(path))

    cmd_out = ansible_module.pki(cli="kra-audit-mod",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='--input {}'.format(path))
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert "PKIException: Bad Request" in result['stderr']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
    ansible_module.command('rm -rf {}'.format(path))


def test_pki_kra_audit_mod_modify_and_check_for_audit_logs(ansible_module):
    """
    :Title: pki kra-audit-mod modify and check for audit logs
    :Description: Issue pki kra-audit-mod modify and check for audit logs
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c SECret.123
           -n "PKI KRA Administrator for Example.Org" kra-audit-mod --action enable
        2. systemctl restart topology-02-KRA
        3. Assert the CS.cfg to confirm that it should be enabled
        4. Issue the certificate
        5. Check that AUDIT_LOG_SIGNING event get generated.
        6. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c SECret.123
           -n "PKI KRA Administrator for Example.Org" kra-audit-mod --action disable
        7. systemctl restart topology-02-KRA
        8. Issue the certificate.
        9. Assert the event AUDIT_LOG_SIGNING should not be present.
    :Expected results:
        1. It should generate the audit log signing event for cert request

    """
    # Show the audit conf
    path = '/tmp/audit'
    cmd_out = ansible_module.pki(cli="kra-audit-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='--output {}'.format(path))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Stored audit configuration into {}".format(path) in result['stdout']
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Update the signed from false to true
    ansible_module.replace(dest=path, regexp='<Signed>false</Signed>', replace='<Signed>true</Signed>')

    # Restore the changes as original
    cmd_out = ansible_module.pki(cli="kra-audit-mod",
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.KRA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                     extra_args='--input {}'.format(path))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Modified audit configuration" in result['stdout']
            assert "Signed: true" in result['stdout']
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Restart the server
    ansible_module.command('systemctl restart pki-tomcatd@{}'.format(constants.KRA_INSTANCE_NAME))
    time.sleep(5)

    # Assert the CS.cfg to confirm that it should be enabled.

    instance_path = 'cat /var/lib/pki/{}/conf/{}/CS.cfg'.format(constants.KRA_INSTANCE_NAME, 'kra')
    cmd = ansible_module.command(instance_path)
    for result in cmd.values():
        if result['rc'] == 0:
            assert "log.instance.SignedAudit.logSigning=true" in result['stdout']
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Issue the certificate

    user = 'testUserCert'
    fullName = 'testUserCert'
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

    # Remove the user
    userop.remove_user(ansible_module, user, subsystem='kra')

    # Check that AUDIT_LOG_SIGNING event get generated

    command = 'tail -n 15 /var/log/pki/{}/{}/signedAudit/kra_cert-kra_audit'.format(constants.KRA_INSTANCE_NAME, 'kra')
    cmd_out = ansible_module.command(command)
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "AUDIT_LOG_SIGNING" in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Disable the audit log signing.

    ansible_module.replace(dest=path, regexp='<Signed>true</Signed>', replace='<Signed>false</Signed>')
    ansible_module.replace(dest=path, regexp='disabled', replace='enabled')
    cmd_out = ansible_module.pki(cli="kra-audit-mod",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='--input {}'.format(path))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Modified audit configuration" in result['stdout']
            assert "Status: Enabled" in result['stdout']
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Restart the server
    ansible_module.command('systemctl restart pki-tomcatd@{}'.format(constants.KRA_INSTANCE_NAME))
    time.sleep(5)

    # Issue the certificate

    user = 'testUserCert'
    fullName = 'testUserCert'
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

    # Remove the user
    userop.remove_user(ansible_module, user, subsystem='kra')

    # Check that AUDIT_LOG_SIGNING event get generated
    command = 'tail -n 15 /var/log/pki/{}/{}/signedAudit/kra_cert-kra_audit'.format(constants.KRA_INSTANCE_NAME, 'kra')
    cmd_out = ansible_module.command(command)
    for result in cmd_out.values():
        if result['rc'] == 0:
            if "AUDIT_LOG_SIGNING" not in result['stdout']:
                log.info('Successfully ran : {}'.format(result['cmd']))
            else:
                assert "AUDIT_LOG_SIGNING" in result['stdout']
                log.error(result['stdout'])
                log.error(result['stderr'])
                pytest.fail()
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Restore the config to original

    ansible_module.replace(dest=path, regexp='<Signed>false</Signed>', replace='<Signed>true</Signed>')
    cmd_out = ansible_module.pki(cli="kra-audit-mod",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='--input {}'.format(path))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Modified audit configuration" in result['stdout']
            assert "Status: Enabled" in result['stdout']
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    ansible_module.command('rm -rf {}'.format(path))
