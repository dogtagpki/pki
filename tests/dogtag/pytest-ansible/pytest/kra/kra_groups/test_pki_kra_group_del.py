"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI KRA-GROUP CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki kra-group cli commands needs to be tested:
#   pki kra-group-del
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


@pytest.mark.parametrize('args', ['--help', 'asdf', ''])
def test_pki_kra_group_del_help(ansible_module, args):
    """
    :Title: Test pki kra-group-del  --help command.
    :Description: test pki kra-group-del --help command
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c
           SECret.123 -n "PKI KRA Administrator for Example.Org"
           kra-group-del --help
        2. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c
           SECret.123 -n "PKI KRA Administrator for Example.Org"
           kra-group-del asdf
        3. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c
           SECret.123 -n "PKI KRA Administrator for Example.Org"
           kra-group-del
    :Expected results:
        1. It should return help message.
    """
    cmd_out = ansible_module.pki(cli="kra-group-del",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='{}'.format(args))
    for result in cmd_out.values():
        if args == '--help':
            assert result['rc'] == 0
            assert "usage: kra-group-del <Group ID> [OPTIONS...]" in result['stdout']
            assert "--help" in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        elif args == 'asdf':
            assert result['rc'] >= 1
            assert 'ResourceNotFoundException: No such object.' in result['stderr']
            log.info("Successfully run : '{}'".format(result['cmd']))
        elif args == '':
            assert result['rc'] >= 1
            assert 'ERROR: No Group ID specified.' in result['stderr']
            log.info("Successfully ran : '{}'".format(result['cmd']))


@pytest.mark.parametrize('valid_groups', ['kra_group', 'Test Group', 'abcdefghijklmnopqrstuvwxyx12345678',
                                          'abc#', 'abc$', 'abc@', 'abc?', '0'])
def test_pki_delete_valid_groups(ansible_module, valid_groups):
    """
    :Title: Test pki delete valid groups
    :Description: test pki delete valid groups
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c
           SECret.123 -n "PKI KRA Administrator for Example.Org"
           kra-group-del <valid_groups>

    :Expected results:
        1. It should delete the valid groups created using valid cert
    """
    # Add the Groups
    cmd_out = ansible_module.pki(cli="kra-group-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='"{}"'.format(valid_groups))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added group "{}"'.format(valid_groups) in result['stdout']
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
                                 extra_args='"{}"'.format(valid_groups))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Deleted group "{}"'.format(valid_groups) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Validate the group
    cmd_out = ansible_module.pki(cli="kra-group-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='"{}"'.format(valid_groups))
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert 'GroupNotFoundException: Group {} not found'.format(valid_groups) in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


def test_pki_add_and_delete_case_sensitive_group_id(ansible_module):
    """
    :Title: Test pki add and delete case sensitive group id
    :Description: test pki add and delete case sensitive group id
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c
           SECret.123 -n "PKI KRA Administrator for Example.Org"
           kra-group-add group_abc --description "test_group"
        2. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c
           SECret.123 -n "PKI KRA Administrator for Example.Org"
           kra-group-del group_abc

    :Expected results:
        1. It should add and delete case sensitive group id.
    """
    # Add the Groups
    cmd_out = ansible_module.pki(cli="kra-group-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='"{}" --description "{}"'.format('group_abc', 'test_group'))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added group "group_abc"' in result['stdout']
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
                                 extra_args='"{}"'.format('group_abc'))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Deleted group "group_abc"' in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Validate the group
    cmd_out = ansible_module.pki(cli="kra-group-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='"group_abc"')
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert 'GroupNotFoundException: Group group_abc not found' in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


def test_pki_delete_group_when_required_option_group_id_is_missing(ansible_module):
    """
    :Title: Test pki delete group when required group id is missing
    :Description: test pki delete group when required group id is missing
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c
           SECret.123 -n "PKI KRA Administrator for Example.Org"
           kra-group-del

    :Expected results:
        1. It should return exception
    """
    # Delete the group
    cmd_out = ansible_module.pki(cli="kra-group-del",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK))
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert 'ERROR: No Group ID specified.' in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


def test_pki_delete_group_with_maximum_length_in_group_id(ansible_module):
    """
    :Title: pki kra-group-del: delete group with maximum length in group id
    :Description: Issue pki kra-group-del: delete group with maximum length in group id
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c SECret.123
           -n "PKI KRA Administrator for Example.Org" kra-group-add <maximum length of group id> --description "group1"
        2. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c SECret.123
           -n "PKI KRA Administrator for Example.Org" kra-group-del <maximum length of group id>

    :Expected results:
        1. It should delete the group with maximum length in group id

    """
    # Add the group with maximum length in it
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

    # Validate the group
    cmd_out = ansible_module.pki(cli="kra-group-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='"{}"'.format(group_name))
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert 'GroupNotFoundException: Group {} not found'.format(group_name) in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


@pytest.mark.parametrize("valid_user_cert", ["KRA_AdminV", "KRA_AgentV", "KRA_AuditV"])
def test_pki_kra_group_del_with_valid_user_cert(valid_user_cert, ansible_module):
    """
    :Title: pki kra-group-del with different valid user's cert
    :Description: Executing pki kra-group-del using valid user cert should pass
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AdminV" kra-group-del group9
        2. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AgentV" kra-group-del group9
        3. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AuditV" kra-group-del group9

    :Expected results:
        1. It should del group using KRA_AdminV cert

    """
    cmd_out = ansible_module.pki(cli="kra-group-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='{}'.format('group111'))
    for result in cmd_out.values():
        assert 'Added group "group111"' in result['stdout']
        log.info('Successfully ran : {}'.format(result['cmd']))

    # Delete the group
    cmd_out = ansible_module.pki(cli="kra-group-del",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(valid_user_cert),
                                 extra_args='{}'.format('group111'))
    for result in cmd_out.values():
        if valid_user_cert == 'KRA_AdminV':
            assert 'Deleted group "group111"' in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))

        elif valid_user_cert in ['KRA_AgentV', 'KRA_AuditV']:
            assert result['rc'] >= 1
            assert 'ForbiddenException: Authorization Error' in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))

            # Delete the created group
            cmd_out = ansible_module.pki(cli="kra-group-del",
                                         nssdb=constants.NSSDB,
                                         dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                         port=constants.KRA_HTTP_PORT,
                                         hostname=constants.MASTER_HOSTNAME,
                                         certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                         extra_args='{}'.format('group111'))
            for result in cmd_out.values():
                assert 'Deleted group "group111"' in result['stdout']
                log.info('Successfully ran : {}'.format(result['cmd']))


@pytest.mark.parametrize("revoked_user_cert", ["KRA_AdminR", "KRA_AgentR", "KRA_AuditR"])
def test_pki_kra_group_del_with_revoked_user_cert(revoked_user_cert, ansible_module):
    """
    :Title: pki kra-group-del with different revoked user's cert
    :Description: Executing pki kra-group-del using revoked user cert
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AdminR" kra-group-del group10
        2. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AgentR" kra-group-del group10
        3. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AuditR" kra-group-del group10
    :Expected results:
        1. It should throw Revoked Exception.

    """
    cmd_out = ansible_module.pki(cli="kra-group-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='{}'.format('group222'))
    for result in cmd_out.values():
        assert 'Added group "group222"' in result['stdout']
        log.info('Successfully ran : {}'.format(result['cmd']))

    # Delete the group with different revoked cert
    cmd_out = ansible_module.pki(cli="kra-group-del",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(revoked_user_cert),
                                 extra_args='{}'.format('group222'))
    for result in cmd_out.values():
        if result['rc'] > 0:
            assert 'SEVERE: FATAL: SSL alert received: CERTIFICATE_REVOKED\nIOException: ' \
                   'SocketException cannot read on socket: Error reading from socket: ' \
                   '(-12270) SSL peer rejected your certificate as revoked.' in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))

            # Delete the created group
            cmd_out = ansible_module.pki(cli="kra-group-del",
                                         nssdb=constants.NSSDB,
                                         dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                         port=constants.KRA_HTTP_PORT,
                                         hostname=constants.MASTER_HOSTNAME,
                                         certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                         extra_args='{}'.format('group222'))
            for result in cmd_out.values():
                assert 'Deleted group "group222"' in result['stdout']
                log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail('Failed to run : {}'.format(result['cmd']))


@pytest.mark.parametrize("expired_user_cert", ["KRA_AdminE", "KRA_AgentE", "KRA_AuditE"])
def test_pki_kra_group_del_with_expired_user_cert(expired_user_cert, ansible_module):
    """
    :Title: pki kra-group-del with different user's expired cert
    :Description: Executing pki kra-group-del using expired user cert
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AdminE" kra-group-del group11
        2. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AgentE" kra-group-del group11
        3. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AuditE" kra-group-del group11
    :Expected results:
        1. It should return an Expired Exception.

    """
    # Delete the group with Expired cert's
    cmd_out = ansible_module.pki(cli="kra-group-del",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(expired_user_cert),
                                 extra_args='{}'.format('ClonedSubsystems'))
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


def test_pki_kra_group_del_as_anonymous_user(ansible_module):
    """
    :Title: pki kra-group-del as anonymous user
    :Description: Execute pki kra-group-del as anonymous user should fail
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 kra-group-del Administrators
    :Expected results:
        2. It should return Forbidden Exception

    """
    command = 'pki -d {} -c {} -h {} -P http -p {} kra-group-del {}'.format(
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


def test_pki_kra_group_del_with_invalid_user(ansible_module):
    """
    :Title: pki kra-group-del with invalid user's cert
    :Description: Issue pki kra-group-del with invalid user
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c SECret.123
           -u pki_user -w Secret123 kra-group-del Administrators
    :Expected results:
        1. It should return an Unauthorised Exception.

    """
    command_out = ansible_module.pki(cli="kra-group-del",
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


def test_pki_kra_group_del_with_normal_user_cert(ansible_module):
    """
    :Title: pki kra-group-del with normal user cert
    :Description: Issue pki kra-group-del with normal user cert should fail
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Add User
        2. Generate User Cert
        3. Add Cert to User
        4. Add User cert in database
        5. Delete group using the same user cert
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

    cert_import = 'pki -d {} -c {} -P http -p {} -h {} client-cert-import "{}" ' \
                  '--serial {}'.format(constants.NSSDB,
                                       constants.CLIENT_DIR_PASSWORD,
                                       constants.CA_HTTP_PORT,
                                       constants.MASTER_HOSTNAME, user,
                                       cert_id)
    ansible_module.command(cert_import)

    cmd_out = ansible_module.pki(cli="kra-group-del",
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

    # Remove the user
    userop.remove_user(ansible_module, user, subsystem='kra')
