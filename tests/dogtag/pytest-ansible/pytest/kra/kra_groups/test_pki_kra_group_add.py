#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI KRA-GROUP CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki kra-group cli commands needs to be tested:
#   pki kra-group-add
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


@pytest.mark.parametrize('args', ['--help', ''])
def test_pki_kra_group_add_help(ansible_module, args):
    """
    :Title: Test pki kra-group-add  --help command.
    :Description: test pki kra-group-add --help command
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c
           SECret.123 -n "PKI KRA Administrator for Example.Org"
           kra-group-add --help
        2. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c
           SECret.123 -n "PKI KRA Administrator for Example.Org"
           kra-group-add

    :Expected results:
        1. It should return help message.
    """
    cmd_out = ansible_module.pki(cli="kra-group-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='{}'.format(args))
    for result in cmd_out.values():
        if args == '--help':
            assert result['rc'] == 0
            assert "usage: kra-group-add <Group ID> [OPTIONS...]" in result['stdout']
            assert "--description <description>   Description" in result['stdout']
            assert '--help' in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        elif args == '':
            assert result['rc'] >= 1
            assert 'ERROR: No Group ID specified.' in result['stderr']
            log.info("Successfully ran : '{}'".format(result['cmd']))


def test_add_group_to_kra(ansible_module):
    """
    :Title: pki kra-group-add: add group to KRA
    :Description: Issue pki kra-group-add: add group to KRA
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c SECret.123
           -n "PKI KRA Administrator for Example.Org" kra-group-add group1 --description "group1"

    :Expected results:
        1. It should add the group to KRA

    """
    # Add the group i.e group1
    group_name = "group3"
    cmd_out = ansible_module.pki(cli="kra-group-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='{} --description {}'.format(group_name, 'group3'))
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


def test_add_group_to_kra_with_maximum_length_in_group_id(ansible_module):
    """
    :Title: pki kra-group-add: add group to KRA with maximum length in group id
    :Description: Issue pki kra-group-add: add group to KRA with maximum length in group id
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c SECret.123
           -n "PKI KRA Administrator for Example.Org" kra-group-add <maximum length of group id> --description "group1"

    :Expected results:
        1. It should add the group with maximum length in group id

    """
    # Add the group
    group_name = binascii.b2a_hex(os.urandom(1000))
    cmd_out = ansible_module.pki(cli="kra-group-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='{} --description {}'.format(group_name, 'group'))
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


@pytest.mark.parametrize('valid_character', ['abc#', 'abc$', 'abc@', 'abc?', '0'])
def test_add_group_to_kra_with_different_symbols_in_group_id(ansible_module, valid_character):
    """
    :Title: pki kra-group-add: add group to KRA with different symbols in group id
    :Description: Issue pki kra-group-add: add group to KRA with different symbols in group id
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c SECret.123
           -n "PKI KRA Administrator of Example.Org" kra-group-add <different_symbols>

    :Expected results:
        1. It should add the group with <valid_symbol> character in it

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


def test_add_group_to_kra_with_maximum_length_in_description(ansible_module):
    """
    :Title: pki kra-group-add: add group to KRA with maximum length in description
    :Description: Issue pki kra-group-add: add group to KRA with maximum length in description
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c SECret.123
           -n "PKI KRA Administrator of Example.Org" kra-group-add group4 --description "<maximum length of group id>"

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
                                 extra_args='{} --description "{}"'.format('group4', group_description))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added group "group4"' in result['stdout']
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
                                 extra_args='{}'.format('group4'))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Deleted group "group4"' in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


def test_add_duplicate_group_to_kra(ansible_module):
    """
    :Title: pki kra-group-add: add duplicate group to KRA
    :Description: Issue pki kra-group-add: add duplicate group to KRA
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c SECret.123
           -n "PKI KRA Administrator of Example.Org" kra-group-add group5
        2. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c SECret.123
           -n "PKI KRA Administrator of Example.Org" kra-group-add group5

    :Expected results:
        1. It should return the conflict exception

    """
    # Add the group
    cmd_out = ansible_module.pki(cli="kra-group-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='{}'.format('group5'))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added group "group5"' in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Add the duplicate group again
    cmd_out = ansible_module.pki(cli="kra-group-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='{}'.format('group5'))
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert 'ConflictingOperationException: Entry already exists.' in result['stderr']
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
                                 extra_args='{}'.format('group5'))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Deleted group "group5"' in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


def test_add_group_to_kra_with_missing_required_option_group_id(ansible_module):
    """
    :Title: pki kra-group-add: add group to KRA with missing required option group id
    :Description: Issue pki kra-group-add: add group to KRA with missing required option group id
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com -c SECret.123
           -n "PKI KRA Administrator of Example.Org" kra-group-add --description "group"

    :Expected results:
        1. It should return no group id specified exception.

    """
    # Add the group without group id
    cmd_out = ansible_module.pki(cli="kra-group-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='--description "{}"'.format('group'))
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert 'ERROR: No Group ID specified.' in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


@pytest.mark.parametrize("valid_user_cert", ["KRA_AdminV", "KRA_AgentV", "KRA_AuditV"])
def test_pki_kra_group_add_with_valid_user_cert(valid_user_cert, ansible_module):
    """
    :Title: pki kra-group-add with different valid user's cert
    :Description: Executing pki kra-group-add using valid user cert should pass
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AdminV" kra-group-add group6
        2. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AgentV" kra-group-add group6
        3. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AuditV" kra-group-add group6

    :Expected results:
        1. It should add group for KRA_AdminV cert

    """
    cmd_out = ansible_module.pki(cli="kra-group-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(valid_user_cert),
                                 extra_args='{}'.format('group6'))
    for result in cmd_out.values():
        if valid_user_cert == 'KRA_AdminV':
            assert 'Added group "group6"' in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))

            # Remove the group
            cmd_out = ansible_module.pki(cli="kra-group-del",
                                         nssdb=constants.NSSDB,
                                         dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                         port=constants.KRA_HTTP_PORT,
                                         hostname=constants.MASTER_HOSTNAME,
                                         certnick='"{}"'.format(valid_user_cert),
                                         extra_args='{}'.format('group6'))
            for result in cmd_out.values():
                if result['rc'] == 0:
                    assert 'Deleted group "group6"' in result['stdout']
                    log.info('Successfully ran : {}'.format(result['cmd']))
                else:
                    log.error(result['stdout'])
                    log.error(result['stderr'])
                    pytest.fail()

        elif valid_user_cert in ['KRA_AgentV', 'KRA_AuditV']:
            assert result['rc'] >= 1
            assert 'ForbiddenException: Authorization Error' in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))


@pytest.mark.parametrize("revoked_user_cert", ["KRA_AdminR", "KRA_AgentR", "KRA_AuditR"])
def test_pki_kra_group_add_with_revoked_user_cert(revoked_user_cert, ansible_module):
    """
    :Title: pki kra-group-add with different revoked user's cert
    :Description: Executing pki kra-group-add using revoked user cert
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AdminR" kra-group-add group2
        2. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AgentR" kra-group-add group2
        3. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AuditR" kra-group-add group2
    :Expected results:
        1. It should throw Unauthorised Exception.

    """
    cmd_out = ansible_module.pki(cli="kra-group-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(revoked_user_cert),
                                 extra_args='{}'.format('group7'))
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
def test_pki_kra_group_add_with_expired_user_cert(expired_user_cert, ansible_module):
    """
    :Title: pki kra-group-add with different user's expired cert
    :Description: Executing pki kra-group-add using expired user cert
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AdminE" kra-group-add group8
        2. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AgentE" kra-group-add group8
        3. pki -d /opt/pki/certdb -P http -p 21080 -h pki1.example.com
           -c SECret.123 -n "KRA_AuditE" kra-group-add group8
    :Expected results:
        1. It should return an Certificate Unknown Exception.

    """
    cmd_out = ansible_module.pki(cli="kra-group-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(expired_user_cert),
                                 extra_args='{}'.format('group8'))
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


def test_add_group_to_kra_with_i18n_character(ansible_module):
    """
    :id: cd551d91-d615-4ee3-840c-b68d6772ac21
    :Title: pki kra-group-add: add group to KRA with i18n character
    :Description: Issue pki kra-group-add: add group to KRA with i18n character
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P https -p 21443 -h pki1.example.com -c SECret.123
           -n "PKI KRA Administrator for Example.Org" kra-group-add 'ÖrjanÄke' --description "ÖrjanÄke"
    :Expected results:
        1. It should add the group to KRA with i18n character
    :Automated: Yes
    """
    # Add the group
    group_name = "ÖrjanÄke"
    cmd_out = ansible_module.pki(cli="kra-group-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTPS_PORT,
                                 protocol='https',
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='"{}" --description "{}"'.format(group_name, group_name))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added group "{}"'.format(group_name) in result['stdout'].encode('utf-8')
            assert 'Group ID: {}'.format(group_name) in result['stdout'].encode('utf-8')
            log.info('Successfully ran : {}'.format(result['cmd'].encode('utf-8')))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Delete the group
    cmd_out = ansible_module.pki(cli="kra-group-del",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.KRA_HTTPS_PORT,
                                 protocol='https',
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='"{}"'.format(group_name))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Deleted group "{}"'.format(group_name) in result['stdout'].encode('utf-8')
            log.info('Successfully ran : {}'.format(result['cmd'].encode('utf-8')))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
