"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI KRA-GROUP CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki kra-group cli commands needs to be tested:
#   pki kra-group-show
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

from pki.testlib.common.certlib import sys
from pki.testlib.common.utils import ProfileOperations, UserOperations
import os, binascii, pytest

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

userop = UserOperations(nssdb=constants.NSSDB)
profop = ProfileOperations(nssdb=constants.NSSDB)
log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)

KRA_GROUPS = ['Data Recovery Manager Agents', 'Subsystem Group',
              'Trusted Managers', 'Administrators', 'Auditors', 'ClonedSubsystems',
              'Security Domain Administrators', 'Enterprise KRA Administrators']


@pytest.mark.parametrize('args', ['--help', 'asdf', ''])
def test_pki_kra_group_show_help(ansible_module, args):
    """
    :Title: Test pki kra-group-show  --help command.
    :Description: test pki kra-group-show --help command
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c
           SECret.123 -n "PKI KRA Administrator for Example.Org"
           kra-group-show --help
        2. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c
           SECret.123 -n "PKI KRA Administrator for Example.Org"
           kra-group-show asdf
        3. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c
           SECret.123 -n "PKI KRA Administrator for Example.Org"
           kra-group-show
    :Expected results:
        1. It should return help message.
    """
    cmd_out = ansible_module.pki(cli="kra-group-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='{}'.format(args))
    for result in cmd_out.values():
        if args == '--help':
            assert result['rc'] == 0
            assert "usage: kra-group-show <Group ID> [OPTIONS...]" in result['stdout']
            assert "--help" in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        elif args == 'asdf':
            assert result['rc'] >= 1
            assert 'GroupNotFoundException: Group asdf not found' in result['stderr']
            log.info("Successfully run : '{}'".format(result['cmd']))
        elif args == '':
            assert result['rc'] >= 1
            assert 'ERROR: No Group ID specified.' in result['stderr']
            log.info("Successfully ran : '{}'".format(result['cmd']))


def test_pki_kra_group_show_all_groups(ansible_module):
    """
    :Title: pki kra-group-show all groups
    :Description: Execute pki kra-group-show information of all the groups
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c
           SECret.123 -n "PKI KRA Administrator for Example.Org" kra-group-show
    :Expected results:
        1. It should return All groups.

    """
    for i in KRA_GROUPS:
        cmd_out = ansible_module.pki(cli="kra-group-show",
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.KRA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                     extra_args='"{}"'.format(i))
        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Group ID: {}'.format(i) in result['stdout']
            else:
                log.error(result['stdout'])
                log.error(result['stderr'])
                pytest.fail()


def test_pki_kra_group_show_as_non_existing_group(ansible_module):
    """
    :Title: pki kra-group-show as non-existing group
    :Description: Issue pki kra-group-show as non-existing group should fail
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c SECret.123
           -n "PKI KRA Administrator for Example.Org" kra-group-show NonExistingGroup
    :Expected results:
        1. It should return a NotFound Exception

    """
    cmd_out = ansible_module.pki(cli="kra-group-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='{}'.format('NonExistingGroup'))
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert 'GroupNotFoundException: Group NonExistingGroup not found' in result['stderr']
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


def test_pki_kra_group_show_as_anonymous_user(ansible_module):
    """
    :Title: pki kra-group-show as anonymous user
    :Description: Execute pki kra-group-show as anonymous user should fail
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 kra-group-show Administrators
    :Expected results:
        2. It should return Forbidden Exception

    """
    command = 'pki -d {} -c {} -h {} -P http -p {} kra-group-show {}'.format(
        constants.NSSDB,
        constants.CLIENT_DIR_PASSWORD,
        constants.MASTER_HOSTNAME,
        constants.KRA_HTTP_PORT, 'Administrators')
    cmd_out = ansible_module.command(command)
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert 'PKIException: Unauthorized' in result['stderr']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


@pytest.mark.parametrize("valid_user_cert", ["KRA_AdminV", "KRA_AgentV", "KRA_AuditV"])
def test_pki_kra_group_show_with_valid_user_cert(valid_user_cert, ansible_module):
    """
    :Title: pki kra-group-show with different valid user's cert
    :Description: Executing pki kra-group-show using valid user cert should pass
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AdminV" kra-group-show Administrators
        2. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AgentV" kra-group-show Administrators
        3. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AuditV" kra-group-show Administrators

    :Expected results:
        1. It should return Certificates

    """
    cmd_out = ansible_module.pki(cli="kra-group-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(valid_user_cert),
                                 extra_args='{}'.format('Administrators'))
    for result in cmd_out.values():
        if valid_user_cert == 'KRA_AdminV':
            assert 'Group "Administrators"' in result['stdout']
            assert 'Group ID: Administrators' in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        elif valid_user_cert in ['KRA_AgentV', 'KRA_AuditV']:
            assert result['rc'] >= 1
            assert 'ForbiddenException: Authorization Error' in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))


@pytest.mark.parametrize("revoked_user_cert", ["KRA_AdminR", "KRA_AgentR", "KRA_AuditR"])
def test_pki_kra_group_show_with_revoked_user_cert(revoked_user_cert, ansible_module):
    """
    :Title: pki kra-group-show with different revoked user's cert
    :Description: Executing pki kra-group-show using revoked user cert
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AdminR" kra-group-show Administrators
        2. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AgentR" kra-group-show Administrators
        3. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AuditR" kra-group-show Administrators
    :Expected results:
        1. It should throw Unauthorised Exception.

    """
    cmd_out = ansible_module.pki(cli="kra-group-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(revoked_user_cert),
                                 extra_args='{}'.format('Administrators'))
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
def test_pki_kra_group_show_with_expired_user_cert(expired_user_cert, ansible_module):
    """
    :Title: pki kra-group-show with different user's expired cert
    :Description: Executing pki kra-group-show using expired user cert
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AdminE" kra-group-show Administrators
        2. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AgentE" kra-group-show Administrators
        3. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AuditE" kra-group-show Administrators
    :Expected results:
        1. It should return an Certificate Unknown Exception.

    """
    cmd_out = ansible_module.pki(cli="kra-group-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(expired_user_cert),
                                 extra_args='{}'.format('Administrators'))
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


def test_pki_kra_group_show_with_invalid_user(ansible_module):
    """
    :Title: pki kra-group-show with invalid user's cert
    :Description: Issue pki kra-group-show with invalid user
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c SECret.123
           -u pki_user -w Secret123 kra-group-show Administrators
    :Expected results:
        1. It should return an Unauthorised Exception.

    """
    command_out = ansible_module.pki(cli="kra-group-show",
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.KRA_HTTP_PORT,
                                     authType='basicAuth',
                                     hostname=constants.MASTER_HOSTNAME,
                                     username='"{}"'.format("pki_user"),
                                     userpassword='"{}"'.format("Secret123"),
                                     extra_args='{}'.format('Administrators'))
    for result in command_out.values():
        if result['rc'] >= 1:
            assert 'PKIException: Unauthorized' in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


def test_pki_kra_group_show_with_normal_user_cert(ansible_module):
    """
    :Title: pki kra-group-show with normal user cert
    :Description: Issue pki kra-group-show with normal user cert should fail
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Add User
        2. Generate User Cert
        3. Add Cert to User
        4. Add User cert in database
        5. Show group using the same user cert
    :Expected results:
        1. It should return an Forbidden Exception.
    """
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

    cert_import = 'pki -d {} -c {} -P http -p {} -h {} client-cert-import "{}" ' \
                  '--serial {}'.format(constants.NSSDB,
                                       constants.CLIENT_DIR_PASSWORD,
                                       constants.CA_HTTP_PORT,
                                       constants.MASTER_HOSTNAME, user,
                                       cert_id)
    ansible_module.command(cert_import)

    cmd_out = ansible_module.pki(cli="kra-group-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(user),
                                 extra_args='{}'.format('Administrators'))
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


def test_add_group_to_kra_and_show_group(ansible_module):
    """
    :Title: pki kra-group-show: add group to KRA and show group
    :Description: Issue pki kra-group-show: add group to KRA and show group
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c SECret.123
           -u pki_user -w Secret123 kra-group-add group1 --description "group1"
        2. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c SECret.123
           -u pki_user -w Secret123 kra-group-show group1
    :Expected results:
        1. It should add and show the added group to kra

    """
    # Add the group i.e group999
    group_name = "group999"
    cmd_out = ansible_module.pki(cli="kra-group-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='{} --description {}'.format(group_name, 'group999'))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added group "{}"'.format(group_name) in result['stdout']
            assert 'Group ID: {}'.format(group_name) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Show the added group
    cmd_out = ansible_module.pki(cli="kra-group-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='{}'.format(group_name))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Group "{}"'.format(group_name) in result['stdout']
            assert 'Group ID: {}'.format(group_name) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Delete the group
    cmd_out = ansible_module.pki(cli="kra-group-del",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='{}'.format(group_name))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Deleted group "{}"'.format(group_name) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


def test_add_group_to_kra_with_maximum_length_of_group_id_and_show_group(ansible_module):
    """
    :Title: pki kra-group-show: add group to KRA with maximum length of group id and show group
    :Description: Issue pki kra-group-show: add group to KRA with maximum length to group id and show group
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c SECret.123
           -n "PKI KRA Administrator of Example.Org" kra-group-add <maximum length of group id> --description "group1"
        2. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c SECret.123
           -n "PKI KRA Administrator of Example.Org" kra-group-show <maximum length of group id>
    :Expected results:
        1. It should add and show the added group to kra

    """
    # Add the group i.e group1
    group_name = binascii.b2a_hex(os.urandom(1000))
    cmd_out = ansible_module.pki(cli="kra-group-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='{} --description {}'.format(group_name, 'group1'))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added group "{}"'.format(group_name) in result['stdout']
            assert 'Group ID: {}'.format(group_name) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Show the added group
    cmd_out = ansible_module.pki(cli="kra-group-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='{}'.format(group_name))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Group "{}"'.format(group_name) in result['stdout']
            assert 'Group ID: {}'.format(group_name) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Delete the group
    cmd_out = ansible_module.pki(cli="kra-group-del",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='{}'.format(group_name))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Deleted group "{}"'.format(group_name) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


@pytest.mark.parametrize('valid_character', ['abc#', 'abc$', 'abc@', 'abc?', '0'])
def test_add_group_to_kra_with_different_symbols_in_group_id_and_show_group(ansible_module, valid_character):
    """
    :Title: pki kra-group-show: add group to KRA with different symbols in group id and show group
    :Description: Issue pki kra-group-show: add group to KRA with different symbols in group id and show group
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c SECret.123
           -n "PKI KRA Administrator of Example.Org" kra-group-add <different_symbols>

    :Expected results:
        1. It should add the groups with <valid_symbols> and show the added group to kra

    """
    # Add the group
    cmd_out = ansible_module.pki(cli="kra-group-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='{}'.format(valid_character))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added group "{}"'.format(valid_character) in result['stdout']
            assert 'Group ID: {}'.format(valid_character) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Show the added group
    cmd_out = ansible_module.pki(cli="kra-group-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='{}'.format(valid_character))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Group "{}"'.format(valid_character) in result['stdout']
            assert 'Group ID: {}'.format(valid_character) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Delete the group
    cmd_out = ansible_module.pki(cli="kra-group-del",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='{}'.format(valid_character))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Deleted group "{}"'.format(valid_character) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


def test_add_group_to_kra_with_maximum_length_in_description_and_show_group(ansible_module):
    """
    :Title: pki kra-group-show: add group to KRA with maximum length in description and show group
    :Description: Issue pki kra-group-show: add group to KRA with maximum length in description and show group
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c SECret.123
           -n "PKI KRA Administrator of Example.Org" kra-group-add group1 --description "<maximum length of group id>"
        2. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c SECret.123
           -n "PKI KRA Administrator of Example.Org" kra-group-show group1
    :Expected results:
        1. It should add and show the added group to kra

    """
    # Add the group
    group_description = binascii.b2a_hex(os.urandom(1000))
    cmd_out = ansible_module.pki(cli="kra-group-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='{} --description "{}"'.format('group2', group_description))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added group "group2"' in result['stdout']
            assert 'Description: {}'.format(group_description) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Show the added group
    cmd_out = ansible_module.pki(cli="kra-group-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='{}'.format('group2'))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Group "group2"' in result['stdout']
            assert 'Description: {}'.format(group_description) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Delete the group
    cmd_out = ansible_module.pki(cli="kra-group-del",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='{}'.format('group2'))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Deleted group "group2"' in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
