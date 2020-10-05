"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI CA-GROUP CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki ca-group cli commands needs to be tested:
#   pki ca-group-mod
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
import os, binascii
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
def test_pki_ca_group_mod_help(ansible_module, args):
    """
    :Title: Test pki ca-group-mod  --help command.
    :Description: test pki ca-group-mod --help command
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c
           SECret.123 -n "PKI CA Administrator for Example.Org"
           ca-group-mod --help
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c
           SECret.123 -n "PKI CA Administrator for Example.Org"
           ca-group-mod asdf
        3. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c
           SECret.123 -n "PKI CA Administrator for Example.Org"
           ca-group-mod

    :Expected results:
        1. It should return help message.
    """
    cmd_out = ansible_module.pki(cli="ca-group-mod",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(args))
    for result in cmd_out.values():
        if args == '--help':
            assert result['rc'] == 0
            assert "usage: ca-group-mod <Group ID> [OPTIONS...]" in result['stdout']
            assert "--description <description>   Description" in result['stdout']
            assert '--help' in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        elif args == 'asdf':
            assert result['rc'] >= 1
            assert 'ResourceNotFoundException: Group asdf  not found.' in result['stderr']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        elif args == '':
            assert 'ERROR: No Group ID specified.' in result['stderr']
            log.info("Successfully ran : '{}'".format(result['cmd']))


def test_modify_group_description_in_ca(ansible_module):
    """
    :Title: pki ca-group-mod: modify group description in ca
    :Description: Issue pki ca-group-mod: modify group description in ca
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "PKI CA Administrator for Example.Org" ca-group-add group1 --description "group111"
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "PKI CA Administrator for Example.Org" ca-group-mod group1 --description "test group"

    :Expected results:
        1. It should add and modify the group description

    """
    # Add the group i.e group111
    group_name = "group111"
    cmd_out = ansible_module.pki(cli="ca-group-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --description {}'.format(group_name, 'group111'))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added group "{}"'.format(group_name) in result['stdout']
            assert 'Group ID: {}'.format(group_name) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Modify the group description
    cmd_out = ansible_module.pki(cli="ca-group-mod",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --description "{}"'.format(group_name, 'test group'))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Modified group "{}"'.format(group_name) in result['stdout']
            assert 'Description: test group' in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Delete the group
    cmd_out = ansible_module.pki(cli="ca-group-del",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(group_name))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Deleted group "{}"'.format(group_name) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


def test_modify_group_description_with_character_and_number(ansible_module):
    """
    :Title: pki ca-group-mod: modify group description with character and number
    :Description: Issue pki ca-group-mod: modify group description with character and number
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "PKI CA Administrator for Example.Org" ca-group-add group1 --description "group1"
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "PKI CA Administrator for Example.Org" ca-group-mod group1 --description "abcdefghqrstuvwxyx12345678"

    :Expected results:
        1. It should add and modify the group description

    """
    # Add the group i.e group222
    group_name = "group222"
    cmd_out = ansible_module.pki(cli="ca-group-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --description {}'.format(group_name, 'group222'))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added group "{}"'.format(group_name) in result['stdout']
            assert 'Group ID: {}'.format(group_name) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Modify the group description
    cmd_out = ansible_module.pki(cli="ca-group-mod",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --description "{}"'.format(group_name, 'abcdefghqrstuvwxyx12345678'))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Modified group "{}"'.format(group_name) in result['stdout']
            assert 'Description: abcdefghqrstuvwxyx12345678' in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Delete the group
    cmd_out = ansible_module.pki(cli="ca-group-del",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(group_name))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Deleted group "{}"'.format(group_name) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


def test_modify_group_description_with_maximum_length_and_symbols(ansible_module):
    """
    :Title: pki ca-group-mod: modify group description with maximum length and symbols
    :Description: Issue pki ca-group-mod: modify group description with maximum length and symbols
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "PKI CA Administrator for Example.Org" ca-group-add group1 --description "group1"
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "PKI CA Administrator for Example.Org" ca-group-mod group1 --description "<maximum length & symbols>"

    :Expected results:
        1. It should add and modify the group description

    """
    # Add the group i.e group333
    group_name = "group333"
    cmd_out = ansible_module.pki(cli="ca-group-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --description {}'.format(group_name, 'group333'))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added group "{}"'.format(group_name) in result['stdout']
            assert 'Group ID: {}'.format(group_name) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Modify the group description
    group_description = binascii.b2a_hex(os.urandom(1000))
    cmd_out = ansible_module.pki(cli="ca-group-mod",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --description "{}"'.format(group_name, group_description))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Modified group "{}"'.format(group_name) in result['stdout']
            assert 'Description: {}'.format(group_description) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Delete the group
    cmd_out = ansible_module.pki(cli="ca-group-del",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(group_name))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Deleted group "{}"'.format(group_name) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


def test_modify_group_description_with_dollar_character(ansible_module):
    """
    :Title: pki ca-group-mod: modify group description with $ character
    :Description: Issue pki ca-group-mod: modify group description with $ character
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "PKI CA Administrator for Example.Org" ca-group-add group1 --description "group1"
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "PKI CA Administrator for Example.Org" ca-group-mod group1 --description "test_group$$$$"

    :Expected results:
        1. It should add and modify the group description

    """
    # Add the group i.e group444
    group_name = "group444"
    cmd_out = ansible_module.pki(cli="ca-group-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --description {}'.format(group_name, 'group444'))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added group "{}"'.format(group_name) in result['stdout']
            assert 'Group ID: {}'.format(group_name) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Modify the group description
    cmd_out = ansible_module.pki(cli="ca-group-mod",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --description "{}"'.format(group_name, 'test_group$$$$'))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Modified group "{}"'.format(group_name) in result['stdout']
            assert 'Description: test_group$$$$' in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Delete the group
    cmd_out = ansible_module.pki(cli="ca-group-del",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(group_name))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Deleted group "{}"'.format(group_name) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


def test_modify_group_description_with_missing_required_option_group_id(ansible_module):
    """
    :Title: pki ca-group-mod: modify group description with missing required option group id
    :Description: Issue pki ca-group-mod: modify group description with missing required option group id
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "PKI CA Administrator for Example.Org" ca-group-add group1 --description "group1"
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "PKI CA Administrator for Example.Org" ca-group-mod --description "test_group"

    :Expected results:
        1. It should add and modify the group description

    """
    # Add the group i.e group555
    group_name = "group555"
    cmd_out = ansible_module.pki(cli="ca-group-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --description {}'.format(group_name, 'group555'))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added group "{}"'.format(group_name) in result['stdout']
            assert 'Group ID: {}'.format(group_name) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Modify the group description
    cmd_out = ansible_module.pki(cli="ca-group-mod",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='--description "{}"'.format('test_group'))
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert 'ERROR: No Group ID specified.' in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Delete the group
    cmd_out = ansible_module.pki(cli="ca-group-del",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(group_name))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Deleted group "{}"'.format(group_name) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


def test_modify_group_description_with_empty_description(ansible_module):
    """
    :Title: pki ca-group-mod: modify group description with empty description
    :Description: Issue pki ca-group-mod: modify group description with empty description
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "PKI CA Administrator for Example.Org" ca-group-add group1 --description "group1"
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "PKI CA Administrator for Example.Org" ca-group-mod group1 --description ""

    :Expected results:
        1. It should add and modify the group description

    """
    # Add the group i.e group666
    group_name = "group666"
    cmd_out = ansible_module.pki(cli="ca-group-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --description {}'.format(group_name, 'group666'))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added group "{}"'.format(group_name) in result['stdout']
            assert 'Group ID: {}'.format(group_name) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Modify the group description
    cmd_out = ansible_module.pki(cli="ca-group-mod",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --description "{}"'.format(group_name, ''))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Modified group "{}"'.format(group_name) in result['stdout']
            assert 'Group ID: group666' in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Delete the group
    cmd_out = ansible_module.pki(cli="ca-group-del",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(group_name))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Deleted group "{}"'.format(group_name) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


def test_modify_group_description_with_description_same_as_old_value(ansible_module):
    """
    :Title: pki ca-group-mod: modify group description with description same as old value
    :Description: Issue pki ca-group-mod: modify group description with description same as old value
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "PKI CA Administrator for Example.Org" ca-group-add group1 --description "group1"
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "PKI CA Administrator for Example.Org" ca-group-mod group1 --description "group1"

    :Expected results:
        1. It should add and modify the group description

    """
    # Add the group i.e group777
    group_name = "group777"
    cmd_out = ansible_module.pki(cli="ca-group-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --description {}'.format(group_name, 'group777'))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added group "{}"'.format(group_name) in result['stdout']
            assert 'Group ID: {}'.format(group_name) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Modify the group description
    cmd_out = ansible_module.pki(cli="ca-group-mod",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --description "{}"'.format(group_name, 'group1'))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Modified group "{}"'.format(group_name) in result['stdout']
            assert 'Description: group1' in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Delete the group
    cmd_out = ansible_module.pki(cli="ca-group-del",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(group_name))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Deleted group "{}"'.format(group_name) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


@pytest.mark.parametrize("valid_user_cert", ["CA_AdminV", "CA_AgentV", "CA_AuditV"])
def test_pki_ca_group_mod_with_valid_user_cert(valid_user_cert, ansible_module):
    """
    :Title: pki ca-group-mod with different valid user's cert
    :Description: Executing pki ca-group-mod using valid user cert should pass
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
           -c SECret.123 -n "CA_AdminV" ca-group-mod --description group1
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
           -c SECret.123 -n "CA_AgentV" ca-group-mod --description group1
        3. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
           -c SECret.123 -n "CA_AuditV" ca-group-mod --description group1

    :Expected results:
        1. It should modify group for CA_AdminV cert

    """
    # Add the group
    cmd_out = ansible_module.pki(cli="ca-group-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format('group888'))
    for result in cmd_out.values():
        assert 'Added group "group888"' in result['stdout']
        log.info('Successfully ran : {}'.format(result['cmd']))

    # Modify the group
    cmd_out = ansible_module.pki(cli="ca-group-mod",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(valid_user_cert),
                                 extra_args='{} --description "{}"'.format('group888', 'test_group'))
    for result in cmd_out.values():
        if valid_user_cert == 'CA_AdminV':
            assert 'Modified group "group888"' in result['stdout']
            assert 'Description: test_group' in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))

            # Delete the group
            cmd_out = ansible_module.pki(cli="ca-group-del",
                                         nssdb=constants.NSSDB,
                                         dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                         port=constants.CA_HTTP_PORT,
                                         hostname=constants.MASTER_HOSTNAME,
                                         certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                         extra_args='{}'.format('group888'))
            for result in cmd_out.values():
                if result['rc'] == 0:
                    assert 'Deleted group "group888"' in result['stdout']
                    log.info('Successfully ran : {}'.format(result['cmd']))
                else:
                    log.error(result['stdout'])
                    log.error(result['stderr'])
                    pytest.fail()

        elif valid_user_cert in ['CA_AgentV', 'CA_AuditV']:
            cmd_out = ansible_module.pki(cli="ca-group-mod",
                                         nssdb=constants.NSSDB,
                                         dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                         port=constants.CA_HTTP_PORT,
                                         hostname=constants.MASTER_HOSTNAME,
                                         certnick='"{}"'.format(valid_user_cert),
                                         extra_args='{} --description "{}"'.format('group888', 'test_group'))
            for result in cmd_out.values():
                if result['rc'] >= 1:
                    assert 'ForbiddenException: Authorization Error' in result['stderr']
                    log.info('Successfully ran : {}'.format(result['cmd']))
                else:
                    log.error(result['stdout'])
                    log.error(result['stderr'])
                    pytest.fail()

            # Delete the group
            cmd_out = ansible_module.pki(cli="ca-group-del",
                                         nssdb=constants.NSSDB,
                                         dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                         port=constants.CA_HTTP_PORT,
                                         hostname=constants.MASTER_HOSTNAME,
                                         certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                         extra_args='{}'.format('group888'))
            for result in cmd_out.values():
                if result['rc'] == 0:
                    assert 'Deleted group "group888"' in result['stdout']
                    log.info('Successfully ran : {}'.format(result['cmd']))
                else:
                    log.error(result['stdout'])
                    log.error(result['stderr'])
                    pytest.fail()


@pytest.mark.parametrize("revoked_user_cert", ["CA_AdminR", "CA_AgentR", "CA_AuditR"])
def test_pki_ca_group_mod_with_revoked_user_cert(revoked_user_cert, ansible_module):
    """
    :Title: pki ca-group-mod with different revoked user's cert
    :Description: Executing pki ca-group-mod using revoked user cert
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
           -c SECret.123 -n "CA_AdminR" ca-group-mod --description test_group
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
           -c SECret.123 -n "CA_AgentR" ca-group-mod --description test_group
        3. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
           -c SECret.123 -n "CA_AuditR" ca-group-mod --description test_group
    :Expected results:
        1. It should throw Unauthorised Exception.

    """
    # Add the group
    cmd_out = ansible_module.pki(cli="ca-group-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format('group999'))
    for result in cmd_out.values():
        assert 'Added group "group999"' in result['stdout']
        log.info('Successfully ran : {}'.format(result['cmd']))

    # Modify the group
    cmd_out = ansible_module.pki(cli="ca-group-mod",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(revoked_user_cert),
                                 extra_args='{} --description "{}"'.format('group999', 'test_group'))
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert 'PKIException: Unauthorized' in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

        # Delete the group
        cmd_out = ansible_module.pki(cli="ca-group-del",
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='{}'.format('group999'))
        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Deleted group "group999"' in result['stdout']
                log.info('Successfully ran : {}'.format(result['cmd']))
            else:
                log.error(result['stdout'])
                log.error(result['stderr'])
                pytest.fail()


@pytest.mark.parametrize("expired_user_cert", ["CA_AdminE", "CA_AgentE", "CA_AuditE"])
def test_pki_ca_group_mod_with_expired_user_cert(expired_user_cert, ansible_module):
    """
    :Title: pki ca-group-mod with different user's expired cert
    :Description: Executing pki ca-group-mod using expired user cert
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
           -c SECret.123 -n "CA_AdminE" ca-group-mod --description test_group
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
           -c SECret.123 -n "CA_AgentE" ca-group-mod --description test_group
        3. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
           -c SECret.123 -n "CA_AuditE" ca-group-mod --description test_group
    :Expected results:
        1. It should return an Certificate Unknown Exception.

    """
    # Add the group
    cmd_out = ansible_module.pki(cli="ca-group-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format('group101'))
    for result in cmd_out.values():
        assert 'Added group "group101"' in result['stdout']
        log.info('Successfully ran : {}'.format(result['cmd']))

    # Modify the group
    cmd_out = ansible_module.pki(cli="ca-group-mod",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(expired_user_cert),
                                 extra_args='{} --description "{}"'.format('group101', 'test_group'))
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

        # Delete the group
        cmd_out = ansible_module.pki(cli="ca-group-del",
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='{}'.format('group101'))
        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Deleted group "group101"' in result['stdout']
                log.info('Successfully ran : {}'.format(result['cmd']))
            else:
                log.error(result['stdout'])
                log.error(result['stderr'])
                pytest.fail()


def test_pki_ca_group_mod_as_anonymous_user(ansible_module):
    """
    :Title: pki ca-group-mod as anonymous user
    :Description: Execute pki ca-group-mod as anonymous user should fail
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
           -c SECret.123 ca-group-mod Administrators --description "test_admin"

    :Expected results:
        1. It should return Forbidden Exception

    """
    command = 'pki -d {} -c {} -h {} -P http -p {} ca-group-mod {}'.format(
        constants.NSSDB,
        constants.CLIENT_DIR_PASSWORD,
        constants.MASTER_HOSTNAME,
        constants.CA_HTTP_PORT, 'Administrators', '--description "test_admin"')
    cmd_out = ansible_module.command(command)
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert 'PKIException: Unauthorized' in result['stderr']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


def test_pki_ca_group_mod_with_invalid_user(ansible_module):
    """
    :Title: pki ca-group-mod with invalid user's cert
    :Description: Issue pki ca-group-mod with invalid user
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -u pki_user -w Secret123 ca-group-mod Administrators --description "test_admin"
    :Expected results:
        1. It should return an Unauthorised Exception.

    """
    command_out = ansible_module.pki(cli="ca-group-mod",
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     authType='basicAuth',
                                     hostname=constants.MASTER_HOSTNAME,
                                     username='"{}"'.format("pki_user"),
                                     userpassword='"{}"'.format("Secret123"),
                                     extra_args='{} --description "{}"'.format('Administrators', 'test_admin'))
    for result in command_out.values():
        if result['rc'] >= 1:
            assert 'PKIException: Unauthorized' in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


def test_pki_ca_group_mod_with_normal_user_cert(ansible_module):
    """
    :Title: pki ca-group-mod with normal user cert
    :Description: Issue pki ca-group-mod with normal user cert should fail
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Add User
        2. Generate User Cert
        3. Add Cert to User
        4. Add User cert in database
        5. Modify group using the same user cert
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

    cmd_out = ansible_module.pki(cli="ca-group-mod",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(user),
                                 extra_args='{} --description '"{}"''.format('Administrators', 'test_admin'))
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
