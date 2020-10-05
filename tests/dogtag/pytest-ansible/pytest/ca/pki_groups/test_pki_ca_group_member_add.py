"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI CA-GROUP CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki ca-group cli commands needs to be tested:
#   pki ca-group-member-add
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
import os
import pytest

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
def test_pki_ca_group_member_add_help(ansible_module, args):
    """
    :Title: Test pki ca-group-member-add  --help command.
    :Description: test pki ca-group-member-add --help command
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c
           SECret.123 -n "PKI CA Administrator for Example.Org"
           ca-group-member-add --help
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c
           SECret.123 -n "PKI CA Administrator for Example.Org"
           ca-group-member-add asdf
        3. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c
           SECret.123 -n "PKI CA Administrator for Example.Org"
           ca-group-member-add

    :Expected results:
        1. It should return help message.
    """
    cmd_out = ansible_module.pki(cli="ca-group-member-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(args))
    for result in cmd_out.values():
        if args == '--help':
            assert result['rc'] == 0
            assert "usage: ca-group-member-add <Group ID> <Member ID> [OPTIONS...]" in result['stdout']
            assert "--help" in result['stdout']
        elif args in ['asdf', '']:
            assert result['rc'] >= 1
            assert 'ERROR: Incorrect number of arguments specified.' in result['stderr']
            log.info("Successfully ran : '{}'".format(result['cmd']))


@pytest.mark.parametrize('CA_Groups', ['Certificate Manager Agents', 'Registration Manager Agents', 'Subsystem Group',
                                       'Trusted Managers', 'Administrators', 'Auditors', 'ClonedSubsystems',
                                       'Security Domain Administrators', 'Enterprise CA Administrators',
                                       'Enterprise KRA Administrators',
                                       'Enterprise OCSP Administrators', 'Enterprise TKS Administrators',
                                       'Enterprise RA Administrators', 'Enterprise TPS Administrators'])
def test_pki_add_users_to_available_group(ansible_module, CA_Groups):
    """
    :Title: Test pki ca-group-member-add: Add users to available groups
    :Description: test pki ca-group-member-add: Add users to available groups
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c
           SECret.123 -n "PKI CA Administrator for Example.Org" user-add userall --fullName "userall"
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c
        SECret.123 -n "PKI CA Administrator for Example.Org"
        ca-group-member-add <different groups> userall
        3. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c
        SECret.123 -n "PKI CA Administrator for Example.Org"
        ca-group-member-find Administrators

    :Expected results:
        1. It should create new user
        2. It should add user to specific group
        3. It should delete the groups
    """
    # Add user
    cmd_out = ansible_module.pki(cli="ca-user-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --fullName "{}"'.format('test_user1', 'test_user'))
    for result in cmd_out.values():
        assert 'Added user "test_user1"' in result['stdout']
        assert 'User ID: test_user1' in result['stdout']
        log.info("Successfully ran : {}".format(result['cmd']))

    # Add user to groups
    cmd_out = ansible_module.pki(cli="ca-group-member-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='"{}" {}'.format(CA_Groups, 'test_user1'))
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
    cmd_out = ansible_module.pki(cli="ca-group-member-find",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='"{}" {}'.format(CA_Groups, 'test_user1'))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'User: test_user1' in result['stdout']
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Delete user from groups
    cmd_out = ansible_module.pki(cli="ca-group-member-del",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='"{}" {}'.format(CA_Groups, 'test_user1'))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Deleted group member "test_user1"' in result['stdout']
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Remove the user
    userop.remove_user(ansible_module, 'test_user1', subsystem='ca')


def test_pki_add_users_to_group_multiple_times(ansible_module):
    """
    :Title: Test pki ca-group-member-add: Add users to group multiple times
    :Description: test pki ca-group-member-add: Add users to group multiple times
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c
           SECret.123 -n "PKI CA Administrator for Example.Org" user-add userall --fullName "userall"
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c
        SECret.123 -n "PKI CA Administrator for Example.Org"
        ca-group-member-add Administrators userall
        3. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c
        SECret.123 -n "PKI CA Administrator for Example.Org"
        ca-group-member-add Administrators userall

    :Expected results:
        1. It should create new user
        2. It should add user to specific group
        3. It should return an conflict expection if same user is getting added again.
    """
    # Add user
    cmd_out = ansible_module.pki(cli="ca-user-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --fullName "{}"'.format('userall1', 'userall'))
    for result in cmd_out.values():
        assert 'Added user "userall1"' in result['stdout']
        assert 'User ID: userall1' in result['stdout']
        log.info("Successfully ran : {}".format(result['cmd']))

    # Add user to groups
    cmd_out = ansible_module.pki(cli="ca-group-member-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='"{}" {}'.format('Administrators', 'userall1'))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added group member "userall1"' in result['stdout']
            assert 'User: userall1' in result['stdout']
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Try to add the same user to group again
    cmd_out = ansible_module.pki(cli="ca-group-member-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='"{}" {}'.format('Administrators', 'userall1'))
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert 'ConflictingOperationException: Attribute or value exists.' in result['stderr']
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Remove the user
    userop.remove_user(ansible_module, 'userall1', subsystem='ca')


def test_pki_group_member_add_with_missing_required_option_group_id(ansible_module):
    """
    :Title: pki ca-group-member-add: add group member with missing required option group id
    :Description: pki ca-group-member-add: add group member with missing required option group id
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "PKI CA Administrator of Example.Org" ca-group-member-add Administrators

    :Expected results:
        1. It should return no group id specified exception.

    """
    # Add user
    cmd_out = ansible_module.pki(cli="ca-user-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --fullName "{}"'.format('userall2', 'userall'))
    for result in cmd_out.values():
        assert 'Added user "userall2"' in result['stdout']
        assert 'User ID: userall2' in result['stdout']
        log.info("Successfully ran : {}".format(result['cmd']))

    # Add the group without group id
    cmd_out = ansible_module.pki(cli="ca-group-member-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
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
    userop.remove_user(ansible_module, 'userall2', subsystem='ca')


def test_pki_add_user_to_non_existing_group(ansible_module):
    """
    :Title: pki ca-group-member-add: add user to non existing group
    :Description: pki ca-group-member-add: add user to non existing group
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "PKI CA Administrator of Example.Org" ca-group-member-add NonExistingGroup userall

    :Expected results:
        1. It should return no group id specified exception.

    """
    # Add user
    cmd_out = ansible_module.pki(cli="ca-user-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --fullName "{}"'.format('userall3', 'userall'))
    for result in cmd_out.values():
        assert 'Added user "userall3"' in result['stdout']
        assert 'User ID: userall3' in result['stdout']
        log.info("Successfully ran : {}".format(result['cmd']))

    # Add the user to nonExistingGroup
    cmd_out = ansible_module.pki(cli="ca-group-member-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='"{}" {}'.format('NonExistingGroup', 'userall3'))
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert 'GroupNotFoundException: Group NonExistingGroup not found' in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Remove the user
    userop.remove_user(ansible_module, 'userall3', subsystem='ca')


def test_pki_should_be_able_to_add_user_to_administrators_group(ansible_module):
    """
    :Title: pki ca-group-member-add: Should be able to add user to administrators group
    :Description: pki ca-group-member-add: Should be able to add user to administrators group
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "PKI CA Administrator of Example.Org" ca-group-member-add Administrators userall

    :Expected results:
        1. It should able to add user to Administrators group

    """
    # Add user
    cmd_out = ansible_module.pki(cli="ca-user-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --fullName "{}"'.format('userall4', 'userall'))
    for result in cmd_out.values():
        assert 'Added user "userall4"' in result['stdout']
        assert 'User ID: userall4' in result['stdout']
        log.info("Successfully ran : {}".format(result['cmd']))

    # Add the user in Administrators group
    cmd_out = ansible_module.pki(cli="ca-group-member-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='"{}" {}'.format('Administrators', 'userall4'))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added group member "userall4"' in result['stdout']
            assert 'User: userall4' in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Remove the user in Administrators group
    cmd_out = ansible_module.pki(cli="ca-group-member-del",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='"{}" {}'.format('Administrators', 'userall4'))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Deleted group member "userall4"' in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Remove the user
    userop.remove_user(ansible_module, 'userall4', subsystem='ca')


@pytest.mark.parametrize("valid_user_cert", ["CA_AdminV", "CA_AgentV", "CA_AuditV"])
def test_pki_ca_group_member_add_with_valid_user_cert(valid_user_cert, ansible_module):
    """
    :Title: pki ca-group-member-add with different valid user's cert
    :Description: Executing pki ca-group-member-add using valid user cert should pass
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
           -c SECret.123 -n "CA_AdminV" ca-group-memebr-add Administrators userall
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
           -c SECret.123 -n "CA_AgentV" ca-group-member-add Administrators userall
        3. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
           -c SECret.123 -n "CA_AuditV" ca-group-member-add Administrators userall

    :Expected results:
        1. It should add group for CA_AdminV cert

    """
    # Add user
    cmd_out = ansible_module.pki(cli="ca-user-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --fullName "{}"'.format('userall5', 'userall'))
    for result in cmd_out.values():
        assert 'Added user "userall5"' in result['stdout']
        assert 'User ID: userall5' in result['stdout']
        log.info("Successfully ran : {}".format(result['cmd']))

    # Add user to Administrators group with different valid certs
    cmd_out = ansible_module.pki(cli="ca-group-member-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(valid_user_cert),
                                 extra_args='"{}" {}'.format('Administrators', 'userall5'))
    for result in cmd_out.values():
        if valid_user_cert == 'CA_AdminV':
            assert 'Added group member "userall5"' in result['stdout']
            assert 'User: userall5' in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))

            # Remove the group member
            cmd_out = ansible_module.pki(cli="ca-group-member-del",
                                         nssdb=constants.NSSDB,
                                         dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                         port=constants.CA_HTTP_PORT,
                                         hostname=constants.MASTER_HOSTNAME,
                                         certnick='"{}"'.format(valid_user_cert),
                                         extra_args='"{}" {}'.format('Administrators', 'userall5'))
            for result in cmd_out.values():
                if result['rc'] == 0:
                    assert 'Deleted group member "userall5"' in result['stdout']
                    log.info('Successfully ran : {}'.format(result['cmd']))
                else:
                    log.error(result['stdout'])
                    log.error(result['stderr'])
                    pytest.fail()

        elif valid_user_cert in ['CA_AgentV', 'CA_AuditV']:
            assert result['rc'] >= 1
            assert 'ForbiddenException: Authorization Error' in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))

    # Remove the user
    userop.remove_user(ansible_module, 'userall5', subsystem='ca')


@pytest.mark.parametrize("revoked_user_cert", ["CA_AdminR", "CA_AgentR", "CA_AuditR"])
def test_pki_ca_group_member_add_with_revoked_user_cert(revoked_user_cert, ansible_module):
    """
    :Title: pki ca-group-member-add with different revoked user's cert
    :Description: Executing pki ca-group-member-add using revoked user cert
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
           -c SECret.123 -n "CA_AdminR" ca-group-member-add Administrators userall
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
           -c SECret.123 -n "CA_AgentR" ca-group-member-add Administrators userall
        3. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
           -c SECret.123 -n "CA_AuditR" ca-group-member-add Administrators userall
    :Expected results:
        1. It should throw Unauthorised Exception.

    """
    # Add user
    cmd_out = ansible_module.pki(cli="ca-user-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --fullName "{}"'.format('userall6', 'userall'))
    for result in cmd_out.values():
        assert 'Added user "userall6"' in result['stdout']
        assert 'User ID: userall6' in result['stdout']
        log.info("Successfully ran : {}".format(result['cmd']))

    # Add user to Administrators group using revoked user cert
    cmd_out = ansible_module.pki(cli="ca-group-member-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(revoked_user_cert),
                                 extra_args='"{}" {}'.format('Administrators', 'userall6'))
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert 'PKIException: Unauthorized' in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Remove the user
    userop.remove_user(ansible_module, 'userall6', subsystem='ca')


@pytest.mark.parametrize("expired_user_cert", ["CA_AdminE", "CA_AgentE", "CA_AuditE"])
def test_pki_ca_group_member_add_with_expired_user_cert(expired_user_cert, ansible_module):
    """
    :Title: pki ca-group-member-add with different user's expired cert
    :Description: Executing pki ca-group-member-add using expired user cert
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
           -c SECret.123 -n "CA_AdminE" ca-group-member-add Administrators userall
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
           -c SECret.123 -n "CA_AgentE" ca-group-member-add Administrators userall
        3. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
           -c SECret.123 -n "CA_AuditE" ca-group-member-add Administrators userall
    :Expected results:
        1. It should return an Certificate Unknown Exception.

    """
    # Add user
    cmd_out = ansible_module.pki(cli="ca-user-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --fullName "{}"'.format('userall7', 'userall'))
    for result in cmd_out.values():
        assert 'Added user "userall7"' in result['stdout']
        assert 'User ID: userall7' in result['stdout']
        log.info("Successfully ran : {}".format(result['cmd']))

    # Add user to Administrators group using expired user cert
    cmd_out = ansible_module.pki(cli="ca-group-member-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(expired_user_cert),
                                 extra_args='"{}" {}'.format('Administrators', 'userall7'))
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert "SEVERE: FATAL: SSL alert received: CERTIFICATE_EXPIRED\nIOException: " \
                   "SocketException cannot read on socket: Error reading from socket: " \
                   "(-12269) SSL peer rejected your certificate as expired." in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Remove the user
    userop.remove_user(ansible_module, 'userall7', subsystem='ca')


def test_pki_ca_group_member_add_with_invalid_user(ansible_module):
    """
    :Title: pki ca-group-member-add with invalid user's cert
    :Description: Issue pki ca-group-member-add with invalid user
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -u pki_user -w Secret123 ca-group-member-add Administrators caadmin
    :Expected results:
        1. It should return an Unauthorised Exception.

    """
    # Add user
    cmd_out = ansible_module.pki(cli="ca-user-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --fullName "{}"'.format('userall8', 'userall'))
    for result in cmd_out.values():
        assert 'Added user "userall8"' in result['stdout']
        assert 'User ID: userall8' in result['stdout']
        log.info("Successfully ran : {}".format(result['cmd']))

    # Add user to Administrators group using invalid user
    command_out = ansible_module.pki(cli="ca-group-member-show",
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     authType='basicAuth',
                                     hostname=constants.MASTER_HOSTNAME,
                                     username='"{}"'.format("pki_user"),
                                     userpassword='"{}"'.format("Secret123"),
                                     extra_args='{} {}'.format('Administrators', 'userall8'))
    for result in command_out.values():
        if result['rc'] >= 1:
            assert 'PKIException: Unauthorized' in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Remove the user
    userop.remove_user(ansible_module, 'userall8', subsystem='ca')


def test_pki_ca_group_member_add_with_normal_user_cert(ansible_module):
    """
    :Title: pki ca-group-member-add with normal user cert
    :Description: Issue pki ca-group-member-add with normal user cert should fail
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Add User
        2. Generate User Cert
        3. Add Cert to User
        4. Add User cert in database
        5. Add group using the same user cert
    :Expected results:
        1. It should return an Forbidden Exception.
    """
    user = 'testUserCert'
    fullName = 'testUserCert'
    subject = "UID={},CN={}".format(user, fullName)
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName, subsystem='ca')
    cert_id = userop.process_certificate_request(ansible_module,
                                                 subject=subject,
                                                 request_type='pkcs10',
                                                 algo='rsa',
                                                 keysize='2048',
                                                 profile='caUserCert')
    ansible_module.pki(cli='ca-user-cert-add',
                       nssdb=constants.NSSDB,
                       dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                       port=constants.CA_HTTP_PORT,
                       hostname=constants.MASTER_HOSTNAME,
                       certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                       extra_args='{} --serial {}'.format(user, cert_id))

    cert_import = 'pki -d {} -c {} -P http -p {} -h {} client-cert-import "{}" ' \
                  '--serial {}'.format(constants.NSSDB,
                                       constants.CLIENT_DIR_PASSWORD,
                                       constants.CA_HTTP_PORT,
                                       constants.MASTER_HOSTNAME, user,
                                       cert_id)
    ansible_module.command(cert_import)

    # Add user
    cmd_out = ansible_module.pki(cli="ca-user-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --fullName "{}"'.format('userall9', 'userall'))
    for result in cmd_out.values():
        assert 'Added user "userall9"' in result['stdout']
        assert 'User ID: userall9' in result['stdout']
        log.info("Successfully ran : {}".format(result['cmd']))

    cmd_out = ansible_module.pki(cli="ca-group-member-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(user),
                                 extra_args='{} {}'.format('Administrators', 'userall9'))
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
    userop.remove_user(ansible_module, user, subsystem='ca')

    # Delete the user
    userop.remove_user(ansible_module, 'userall9', subsystem='ca')
