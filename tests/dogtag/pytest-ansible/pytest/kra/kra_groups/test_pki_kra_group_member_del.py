"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI KRA-GROUP CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki kra-group cli commands needs to be tested:
#   pki kra-group-member-del
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
def test_pki_kra_group_member_del_help(ansible_module, args):
    """
    :Title: Test pki kra-group-member-del  --help command.
    :Description: test pki kra-group-member-del --help command
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c
           SECret.123 -n "PKI KRA Administrator for Example.Org"
           kra-group-member-del --help
        2. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c
           SECret.123 -n "PKI KRA Administrator for Example.Org"
           kra-group-member-del asdf
        3. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c
           SECret.123 -n "PKI KRA Administrator for Example.Org"
           kra-group-member-del

    :Expected results:
        1. It should return help message.
    """
    cmd_out = ansible_module.pki(cli="kra-group-member-del",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='{}'.format(args))
    for result in cmd_out.values():
        if args == '--help':
            assert result['rc'] == 0
            assert "usage: kra-group-member-del <Group ID> <Member ID> [OPTIONS...]" in result['stdout']
            assert "--help" in result['stdout']
        elif args in ['asdf', '']:
            assert result['rc'] >= 1
            assert 'ERROR: Incorrect number of arguments specified.' in result['stderr']
            log.info("Successfully ran : '{}'".format(result['cmd']))


@pytest.mark.parametrize('KRA_Groups', ['Data Recovery Manager Agents', 'Subsystem Group',
                                        'Trusted Managers', 'Administrators', 'Auditors', 'ClonedSubsystems',
                                        'Security Domain Administrators', 'Enterprise KRA Administrators'])
def test_pki_delete_user_from_available_group(ansible_module, KRA_Groups):
    """
    :Title: Test pki kra-group-member-del: Del users from available groups
    :Description: test pki kra-group-member-del: Del users from available groups
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c
           SECret.123 -n "PKI KRA Administrator for Example.Org" user-add userall --fullName "userall"
        2. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c
        SECret.123 -n "PKI KRA Administrator for Example.Org"
        kra-group-member-add <different groups> userall
        3. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c
        SECret.123 -n "PKI KRA Administrator for Example.Org"
        kra-group-member-del <different groups> userall

    :Expected results:
        1. It should create new user
        2. It should add user to specific group
        3. It should delete the groups
    """
    # Add user
    cmd_out = ansible_module.pki(cli="kra-user-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='{} --fullName "{}"'.format('test_user1', 'test_user1'))
    for result in cmd_out.values():
        assert 'Added user "test_user1"' in result['stdout']
        assert 'User ID: test_user1' in result['stdout']
        log.info("Successfully ran : {}".format(result['cmd']))

    # Add user to groups
    cmd_out = ansible_module.pki(cli="kra-group-member-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='"{}" {}'.format(KRA_Groups, 'test_user1'))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added group member "test_user1"' in result['stdout']
            assert 'User: test_user1' in result['stdout']
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # find group member
    cmd_out = ansible_module.pki(cli="kra-group-member-find",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='"{}" {}'.format(KRA_Groups, 'test_user1'))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'User: test_user1' in result['stdout']
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Delete user from groups
    cmd_out = ansible_module.pki(cli="kra-group-member-del",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='"{}" {}'.format(KRA_Groups, 'test_user1'))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Deleted group member "test_user1"' in result['stdout']
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Remove the user
    userop.remove_user(ansible_module, 'test_user1', subsystem='kra')


def test_pki_group_member_del_with_missing_required_option_group_id(ansible_module):
    """
    :Title: pki kra-group-member-del: del group member with missing required option group id
    :Description: pki kra-group-member-del: del group member with missing required option group id
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c SECret.123
           -n "PKI KRA Administrator of Example.Org" kra-group-member-del Administrators

    :Expected results:
        1. It should return an error

    """
    # Add user
    cmd_out = ansible_module.pki(cli="kra-user-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='{} --fullName "{}"'.format('userall8', 'userall8'))
    for result in cmd_out.values():
        assert 'Added user "userall8"' in result['stdout']
        assert 'User ID: userall8' in result['stdout']
        log.info("Successfully ran : {}".format(result['cmd']))

    # Delete the group member without group id
    cmd_out = ansible_module.pki(cli="kra-group-member-del",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='"{}"'.format('Administrators'))
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert 'ERROR: Incorrect number of arguments specified.' in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Remove the user
    userop.remove_user(ansible_module, 'userall8', subsystem='kra')


def test_pki_del_user_from_non_existing_group(ansible_module):
    """
    :Title: pki kra-group-member-del: delete user from non existing group
    :Description: pki kra-group-member-del: delete user from non existing group
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c SECret.123
           -n "PKI KRA Administrator of Example.Org" kra-group-member-del NonExistingGroup userall

    :Expected results:
        1. It should return no group id specified exception.

    """
    # Add user
    cmd_out = ansible_module.pki(cli="kra-user-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='{} --fullName "{}"'.format('userall9', 'userall9'))
    for result in cmd_out.values():
        assert 'Added user "userall9"' in result['stdout']
        assert 'User ID: userall9' in result['stdout']
        log.info("Successfully ran : {}".format(result['cmd']))

    # Add the user to nonExistingGroup
    cmd_out = ansible_module.pki(cli="kra-group-member-del",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='"{}" {}'.format('NonExistingGroup', 'userall9'))
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert 'GroupNotFoundException: Group NonExistingGroup not found' in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Remove the user
    userop.remove_user(ansible_module, 'userall9', subsystem='kra')


def test_pki_should_be_able_to_delete_user_from_administrators_group(ansible_module):
    """
    :Title: pki kra-group-member-del: Should be able to delete user from administrators group
    :Description: pki kra-group-member-del: Should be able to delete user from administrators group
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c SECret.123
           -n "PKI KRA Administrator of Example.Org" kra-group-member-del Administrators userall

    :Expected results:
        1. It should able to delete user to Administrators group

    """
    # Add user
    cmd_out = ansible_module.pki(cli="kra-user-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='{} --fullName "{}"'.format('userall10', 'userall10'))
    for result in cmd_out.values():
        assert 'Added user "userall10"' in result['stdout']
        assert 'User ID: userall10' in result['stdout']
        log.info("Successfully ran : {}".format(result['cmd']))

    # Add the user in Administrators group
    cmd_out = ansible_module.pki(cli="kra-group-member-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='"{}" {}'.format('Administrators', 'userall10'))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added group member "userall10"' in result['stdout']
            assert 'User: userall10' in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Delete the user from Administrators group
    cmd_out = ansible_module.pki(cli="kra-group-member-del",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='"{}" {}'.format('Administrators', 'userall10'))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Deleted group member "userall10"' in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Remove the user
    userop.remove_user(ansible_module, 'userall10', subsystem='kra')


@pytest.mark.parametrize("valid_user_cert", ["KRA_AdminV", "KRA_AgentV", "KRA_AuditV"])
def test_pki_kra_group_member_del_with_valid_user_cert(valid_user_cert, ansible_module):
    """
    :Title: pki kra-group-member-del with different valid user's cert
    :Description: Executing pki kra-group-member-del using valid user cert should pass
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AdminV" kra-group-memebr-del Administrators userall
        2. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AgentV" kra-group-member-del Administrators userall
        3. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AuditV" kra-group-member-del Administrators userall

    :Expected results:
        1. It should del group for KRA_AdminV cert

    """
    # Add user
    cmd_out = ansible_module.pki(cli="kra-user-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='{} --fullName "{}"'.format('userall111', 'userall111'))
    for result in cmd_out.values():
        assert 'Added user "userall111"' in result['stdout']
        assert 'User ID: userall111' in result['stdout']
        log.info("Successfully ran : {}".format(result['cmd']))

    # Add user to Administrators group
    cmd_out = ansible_module.pki(cli="kra-group-member-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='"{}" {}'.format('Administrators', 'userall111'))
    for result in cmd_out.values():
        assert 'Added group member "userall111"' in result['stdout']
        assert 'User: userall111' in result['stdout']
        log.info('Successfully ran : {}'.format(result['cmd']))

    # Remove the group member with valid certs
    cmd_out = ansible_module.pki(cli="kra-group-member-del",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(valid_user_cert),
                                 extra_args='"{}" {}'.format('Administrators', 'userall111'))
    for result in cmd_out.values():
        if valid_user_cert == "KRA_AdminV":
            if result['rc'] == 0:
                assert 'Deleted group member "userall111"' in result['stdout']
                log.info('Successfully ran : {}'.format(result['cmd']))
            else:
                log.error(result['stdout'])
                log.error(result['stderr'])
                pytest.fail()

        elif valid_user_cert in ['KRA_AgentV', 'KRA_AuditV']:
            assert result['rc'] >= 1
            assert 'ForbiddenException: Authorization Error' in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))

            # Remove the group member with admin cert
            cmd_out = ansible_module.pki(cli="kra-group-member-del",
                                         nssdb=constants.NSSDB,
                                         dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                         port=constants.KRA_HTTP_PORT,
                                         hostname=constants.MASTER_HOSTNAME,
                                         certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                         extra_args='"{}" {}'.format('Administrators', 'userall111'))
            for result in cmd_out.values():
                if valid_user_cert == "KRA_AdminV":
                    if result['rc'] == 0:
                        assert 'Deleted group member "userall111"' in result['stdout']
                        log.info('Successfully ran : {}'.format(result['cmd']))
                    else:
                        log.error(result['stdout'])
                        log.error(result['stderr'])
                        pytest.fail()
    # Remove the user
    userop.remove_user(ansible_module, 'userall111', subsystem='kra')


@pytest.mark.parametrize("revoked_user_cert", ["KRA_AdminR", "KRA_AgentR", "KRA_AuditR"])
def test_pki_kra_group_member_del_with_revoked_user_cert(revoked_user_cert, ansible_module):
    """
    :Title: pki kra-group-member-del with different revoked user's cert
    :Description: Executing pki kra-group-member-del using revoked user cert
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AdminR" kra-group-member-del Administrators userall
        2. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AgentR" kra-group-member-del Administrators userall
        3. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AuditR" kra-group-member-del Administrators userall
    :Expected results:
        1. It should throw Unauthorised Exception.

    """
    # Add user
    cmd_out = ansible_module.pki(cli="kra-user-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='{} --fullName "{}"'.format('userall12', 'userall12'))
    for result in cmd_out.values():
        assert 'Added user "userall12"' in result['stdout']
        assert 'User ID: userall12' in result['stdout']
        log.info("Successfully ran : {}".format(result['cmd']))

    # Add user to Administrators group
    cmd_out = ansible_module.pki(cli="kra-group-member-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='"{}" {}'.format('Administrators', 'userall12'))
    for result in cmd_out.values():
        assert 'Added group member "userall12"' in result['stdout']
        assert 'User: userall12' in result['stdout']
        log.info('Successfully ran : {}'.format(result['cmd']))

    # Delete the group member with revoked certs
    cmd_out = ansible_module.pki(cli="kra-group-member-del",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(revoked_user_cert),
                                 extra_args='"{}" {}'.format('Administrators', 'userall12'))
    for result in cmd_out.values():
        if result['rc'] > 0:
            assert 'SEVERE: FATAL: SSL alert received: CERTIFICATE_REVOKED\nIOException: ' \
                   'SocketException cannot read on socket: Error reading from socket: ' \
                   '(-12270) SSL peer rejected your certificate as revoked.' in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))

            # Remove the group member with admin cert
            cmd_out = ansible_module.pki(cli="kra-group-member-del",
                                         nssdb=constants.NSSDB,
                                         dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                         port=constants.KRA_HTTP_PORT,
                                         hostname=constants.MASTER_HOSTNAME,
                                         certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                         extra_args='"{}" {}'.format('Administrators', 'userall12'))
            for result in cmd_out.values():
                if result['rc'] == 0:
                    assert 'Deleted group member "userall12"' in result['stdout']
                    log.info('Successfully ran : {}'.format(result['cmd']))
                else:
                    log.error(result['stdout'])
                    log.error(result['stderr'])
                    pytest.fail()

            # Remove the user
            userop.remove_user(ansible_module, 'userall12', subsystem='kra')
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail('Failed to run : {}'.format(result['cmd']))


@pytest.mark.parametrize("expired_user_cert", ["KRA_AdminE", "KRA_AgentE", "KRA_AuditE"])
def test_pki_kra_group_member_del_with_expired_user_cert(expired_user_cert, ansible_module):
    """
    :Title: pki kra-group-member-del with different user's expired cert
    :Description: Executing pki kra-group-member-del using expired user cert
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AdminE" kra-group-member-del Administrators userall
        2. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AgentE" kra-group-member-del Administrators userall
        3. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AuditE" kra-group-member-del Administrators userall
    :Expected results:
        1. It should return an Certificate Unknown Exception.

    """
    # Delete user from Administrators group using expired user cert
    cmd_out = ansible_module.pki(cli="kra-group-member-del",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(expired_user_cert),
                                 extra_args='"{}" {}'.format('Administrators', 'kraadmin'))
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


def test_pki_kra_group_member_del_with_invalid_user(ansible_module):
    """
    :Title: pki kra-group-member-del with invalid user's cert
    :Description: Issue pki kra-group-member-del with invalid user
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c SECret.123
           -u pki_user -w Secret123 kra-group-member-del Administrators kraadmin
    :Expected results:
        1. It should return an Unauthorised Exception.

    """

    # Delete user from Administrators group using invalid user
    command_out = ansible_module.pki(cli="kra-group-member-del",
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.KRA_HTTP_PORT,
                                     authType='basicAuth',
                                     hostname=constants.MASTER_HOSTNAME,
                                     username='"{}"'.format("pki_user"),
                                     userpassword='"{}"'.format("Secret123"),
                                     extra_args='{} {}'.format('Administrators', 'kraadmin'))
    for result in command_out.values():
        if result['rc'] >= 1:
            assert 'PKIException: Unauthorized' in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


def test_pki_kra_group_member_del_with_normal_user_cert(ansible_module):
    """
    :Title: pki kra-group-member-del with normal user cert
    :Description: Issue pki kra-group-member-del with normal user cert should fail
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
    ansible_module.expect(
        command='pki -d {} -c {} -h {} -p {} -P "https" -n "{}" kra-user-cert-add {} --serial {}'.format(
            constants.NSSDB, constants.CA_PASSWORD, constants.MASTER_HOSTNAME, constants.KRA_HTTPS_PORT,
            constants.KRA_ADMIN_NICK, user, cert_id),
        responses={"CA server URL .*": "https://{}:{}".format(constants.MASTER_HOSTNAME, constants.CA_HTTPS_PORT)})

    cert_import = 'pki -d {} -c {} -P http -p {} -h {} client-cert-import "{}" ' \
                  '--serial {}'.format(constants.NSSDB,
                                       constants.CLIENT_DIR_PASSWORD,
                                       constants.CA_HTTP_PORT,
                                       constants.MASTER_HOSTNAME, user,
                                       cert_id)
    ansible_module.command(cert_import)

    # Add user
    cmd_out = ansible_module.pki(cli="kra-user-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='{} --fullName "{}"'.format('userall14', 'userall14'))
    for result in cmd_out.values():
        assert 'Added user "userall14"' in result['stdout']
        assert 'User ID: userall14' in result['stdout']
        log.info("Successfully ran : {}".format(result['cmd']))

    # Add user to Administrators group
    cmd_out = ansible_module.pki(cli="kra-group-member-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='"{}" {}'.format('Administrators', 'userall14'))
    for result in cmd_out.values():
        assert 'Added group member "userall14"' in result['stdout']
        assert 'User: userall14' in result['stdout']
        log.info('Successfully ran : {}'.format(result['cmd']))

    # Delete user from Administrators group using the same cert
    cmd_out = ansible_module.pki(cli="kra-group-member-del",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(user),
                                 extra_args='{} {}'.format('Administrators', 'userall14'))
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert "ForbiddenException: Authorization Error" in result['stderr']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Remove the cert from nssdb
    userop.remove_client_cert(ansible_module, user, subsystem='ca')

    # Remove the user
    userop.remove_user(ansible_module, user, subsystem='kra')

    # Remove the group member using admin cert after fail
    cmd_out = ansible_module.pki(cli="kra-group-member-del",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='"{}" {}'.format('Administrators', 'userall14'))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Deleted group member "userall14"' in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Remove the user
    userop.remove_user(ansible_module, 'userall14', subsystem='kra')
