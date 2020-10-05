#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI KRA KEY CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following kra-key-mod cli commands needs to be tested:
#   pki kra-key-mod
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Amol Kahat <akahat@redhat.com>
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
import os
import random
import sys

import pytest

from pki.testlib.common import utils

if os.path.isfile('/tmp/test_dir/constants.py'):
    sys.path.append('/tmp/test_dir')
    import constants

userop = utils.UserOperations(nssdb=constants.NSSDB)
log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
TOPOLOGY = constants.CA_INSTANCE_NAME.split("-")[1]
key_library = utils.pki_key_library()

pki_cmd = 'kra-key-mod'
if TOPOLOGY != '01':
    CA_SUBJECT = 'CN=CA Signing Certificate,OU={},O={}'.format(constants.CA_INSTANCE_NAME,
                                                               constants.CA_SECURITY_DOMAIN_NAME)
else:
    CA_SUBJECT = 'CN=CA Signing Certificate,OU={},O={}'.format('pki-tomcat',
                                                               constants.CA_SECURITY_DOMAIN_NAME)
basic_pki_cmd_ca = 'pki -d {} -c {} -p {} -n "{}" '.format(constants.NSSDB,
                                                           constants.CLIENT_DIR_PASSWORD,
                                                           constants.CA_HTTPS_PORT,
                                                           constants.CA_ADMIN_NICK)

group_del = 'pki -d {} -c {} -p {} -n "{}" ' \
            'ca-group-del '.format(constants.NSSDB, constants.CLIENT_DIR_PASSWORD,
                                   constants.CA_HTTPS_PORT, constants.CA_ADMIN_NICK)

client_cert_del = 'pki -d {} -c {} client-cert-del '.format(constants.NSSDB,
                                                            constants.CLIENT_DIR_PASSWORD)

key_types = ['AES', 'RSA', 'DSA']
key_lengths = {'AES': 128, 'RSA': 2048, 'DSA': 1024}


@pytest.mark.parametrize('args', ['--help', '', 'asdfa'])
def test_pki_kra_key_mod_help_message(ansible_module, args):
    """
    :Title: Test pki kra-key-mod with --help, '' and asdfa params
    :Description: Test pki kra-key-mod with --help, '' and asdfa params
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki kra-key-mod --help
        2. pki kra-key-mod ''
        3. pki kra-key-mod asdfa
    :ExpectedResults:
        1. It should show help message
        2. It should throw an Exception
        3. It should throw an Exception
    """

    help_out = ansible_module.pki(cli=pki_cmd,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  port=constants.KRA_HTTP_PORT,
                                  hostname=constants.MASTER_HOSTNAME,
                                  certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                  extra_args=args)
    for result in help_out.values():
        if args == '--help':
            assert "usage: kra-key-mod <Key ID> --status <status> [OPTIONS...]" in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        elif args == '':
            assert 'ERROR: No Key ID specified.' in result['stderr']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            assert 'ERROR: Missing key status' in result['stderr']
            log.info("Successfully run: {}".format(result['cmd']))


@pytest.mark.parametrize('key_type', key_types)
def test_pki_kra_key_mod_modify_key_status(ansible_module, key_type):
    """
    :Title: Test pki kra-key-mod Modify status of valid key from active to inactive
    :Description: Test pki kra-key-mod, Modify status of valid key from active to inactive
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki kra-key-generate --key-algorithm AES --key-size 256
        2. pki kra-key-review <request_id> --action approve
        3. pki kra-key-mod <key_id> --action inactive
    :ExpectedResults:
        1. Key status should changed to inactive
    """
    clientid = 'testuser21071_{}'.format(random.randint(1111, 99999999))
    key_size = key_lengths.get(key_type)
    key_id = key_library.generate_key(ansible_module, key_size=key_size, algo=key_type,
                                      client_key_id=clientid, action='approve')
    key_library.modify_key_status(ansible_module, key_id['key_id'], status='active')

    help_out = ansible_module.pki(cli=pki_cmd,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  port=constants.KRA_HTTP_PORT,
                                  hostname=constants.MASTER_HOSTNAME,
                                  certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                  extra_args='{} --status inactive'.format(key_id.get('key_id')))
    for result in help_out.values():
        if result['rc'] == 0:
            assert 'Key ID: {}'.format(key_id.get('key_id')) in result['stdout']
            assert 'Client Key ID: {}'.format(clientid) in result['stdout']
            assert 'Status: inactive' in result['stdout']
            assert 'Algorithm: {}'.format(key_type) in result['stdout']
            assert 'Size: {}'.format(key_size) in result['stdout']
            assert 'Owner: {}'.format(constants.KRA_ADMIN_USERNAME) in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


@pytest.mark.parametrize('key_type', key_types)
def test_pki_kra_key_mod_modify_key_status_inactive_to_active(ansible_module, key_type):
    """
    :Title: Test pki kra-key-mod Modify status of valid key from active to inactive again back to active
    :Description: Test pki kra-key-mod, Modify status of valid key from active to inactive again back to active
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki kra-key-generate --key-algorithm AES --key-size 256
        2. pki kra-key-review <request_id> --action approve
        3. pki kra-key-mod <key_id> --action inactive
        4. pki kra-key-mod <key_id> --action active
    :ExpectedResults:
        1. Key status should changed to inactive
        2. Key status should changed back to active
    """
    clientid = 'testuser21072_{}'.format(random.randint(1111, 99999999))
    key_size = key_lengths.get(key_type)

    key_id = key_library.generate_key(ansible_module, key_size=key_size, algo=key_type,
                                      client_key_id=clientid, action='approve')

    help_out = ansible_module.pki(cli=pki_cmd,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  port=constants.KRA_HTTP_PORT,
                                  hostname=constants.MASTER_HOSTNAME,
                                  certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                  extra_args='{} --status inactive'.format(key_id.get('key_id')))
    for result in help_out.values():
        if result['rc'] == 0:
            assert 'Key ID: {}'.format(key_id.get('key_id')) in result['stdout']
            assert 'Client Key ID: {}'.format(clientid) in result['stdout']
            assert 'Status: inactive' in result['stdout']
            assert 'Algorithm: {}'.format(key_type) in result['stdout']
            assert 'Size: {}'.format(key_size) in result['stdout']
            assert 'Owner: {}'.format(constants.KRA_ADMIN_USERNAME) in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    help_out = ansible_module.pki(cli=pki_cmd,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  port=constants.KRA_HTTP_PORT,
                                  hostname=constants.MASTER_HOSTNAME,
                                  certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                  extra_args='{} --status active'.format(key_id.get('key_id')))
    for result in help_out.values():
        if result['rc'] == 0:
            assert 'Key ID: {}'.format(key_id.get('key_id')) in result['stdout']
            assert 'Client Key ID: {}'.format(clientid) in result['stdout']
            assert 'Status: active' in result['stdout']
            assert 'Algorithm: {}'.format(key_type) in result['stdout']
            assert 'Size: {}'.format(key_size) in result['stdout']
            assert 'Owner: {}'.format(constants.KRA_ADMIN_USERNAME) in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


@pytest.mark.parametrize('status', ['active', 'inactive'])
@pytest.mark.parametrize('key_type', key_types)
def test_pki_kra_key_mod_modify_rejected_key_status(ansible_module, status, key_type):
    """
    :Title: Test pki kra-key-mod Modify status of rejected key to active
    :Description: Test pki kra-key-mod, Modify status of rejected key to active
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki kra-key-generate --key-algorithm AES --key-size 256
        2. pki kra-key-review <request_id> --action rejected
        3. pki kra-key-mod <key_id> --action active
    :ExpectedResults:
        1. Key status should changed to inactive
        2. Key status should changed back to active
    """
    clientid = 'testuser21073_{}'.format(random.randint(1111, 99999999))
    key_size = key_lengths.get(key_type)

    key_id = key_library.generate_key(ansible_module, key_size=key_size, algo=key_type,
                                      client_key_id=clientid, action='approve')
    help_out = ansible_module.pki(cli=pki_cmd,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  port=constants.KRA_HTTP_PORT,
                                  hostname=constants.MASTER_HOSTNAME,
                                  certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                  extra_args='{} --status {}'.format(key_id.get('key_id'), status))
    for result in help_out.values():
        if result['rc'] == 0:
            assert 'Key ID: {}'.format(key_id.get('key_id')) in result['stdout']
            assert 'Client Key ID: {}'.format(clientid) in result['stdout']
            assert 'Status: {}'.format(status) in result['stdout']
            assert 'Algorithm: {}'.format(key_type) in result['stdout']
            assert 'Size: {}'.format(key_size) in result['stdout']
            assert 'Owner: {}'.format(constants.KRA_ADMIN_USERNAME) in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


@pytest.mark.parametrize('status', ['active', 'inactive'])
@pytest.mark.parametrize('key_type', key_types)
def test_pki_kra_key_mod_modify_canceled_key_status(ansible_module, status, key_type):
    """
    :Title: Test pki kra-key-mod Modify status of rejected key to active
    :Description: Test pki kra-key-mod, Modify status of rejected key to active
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki kra-key-generate --key-algorithm AES --key-size 256
        2. pki kra-key-review <request_id> --action rejected
        3. pki kra-key-mod <key_id> --action active
    :ExpectedResults:
        1. Key status should changed to inactive
        2. Key status should changed back to active
    """
    clientid = 'testuser21074_{}'.format(random.randint(1111, 99999999))

    key_size = key_lengths.get(key_type)

    key_id = key_library.generate_key(ansible_module, key_size=key_size, algo=key_type,
                                      client_key_id=clientid, action='approve')
    help_out = ansible_module.pki(cli=pki_cmd,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  port=constants.KRA_HTTP_PORT,
                                  hostname=constants.MASTER_HOSTNAME,
                                  certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                  extra_args='{} --status {}'.format(key_id.get('key_id'), status))
    for result in help_out.values():
        if result['rc'] == 0:
            assert 'Key ID: {}'.format(key_id.get('key_id')) in result['stdout']
            assert 'Client Key ID: {}'.format(clientid) in result['stdout']
            assert 'Status: {}'.format(status) in result['stdout']
            assert 'Algorithm: {}'.format(key_type) in result['stdout']
            assert 'Size: {}'.format(key_size) in result['stdout']
            assert 'Owner: {}'.format(constants.KRA_ADMIN_USERNAME) in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


@pytest.mark.parametrize('key_type', key_types)
def test_pki_kra_key_mod_change_status_to_invalid_status(ansible_module, key_type):
    """
    :Title: Test pki kra-key-mod change status to invalid status
    :Description: Test pki kra-key-mod change status to invalid status
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki kra-key-generate --key-algorithm AES --key-size 128
        2. pki kra-key-mod <req_id> --status asdfas
    :ExpectedResults:
        1. It should throw an error.
    """
    status = 'asdfa'
    clientid = 'testuser21075_{}'.format(random.randint(1111, 99999999))

    key_size = key_lengths.get(key_type)

    key_id = key_library.generate_key(ansible_module, key_size=key_size, algo=key_type,
                                      client_key_id=clientid, action='approve')

    help_out = ansible_module.pki(cli=pki_cmd,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  port=constants.KRA_HTTP_PORT,
                                  hostname=constants.MASTER_HOSTNAME,
                                  certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                  extra_args='{} --status {}'.format(key_id.get('key_id'), status))
    for result in help_out.values():
        if result['rc'] == 0:
            assert 'Key ID: {}'.format(key_id.get('key_id')) in result['stdout']
            assert 'Client Key ID: {}'.format(clientid) in result['stdout']
            assert 'Status: {}'.format(status) in result['stdout']
            assert 'Algorithm: {}'.format(key_type) in result['stdout']
            assert 'Size: {}'.format(key_size) in result['stdout']
            assert 'Owner: {}'.format(constants.KRA_ADMIN_USERNAME) in result['stdout']
            log.error("Failed to run: {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
        else:
            assert "IllegalArgumentException: Invalid status value." in result['stderr']
            log.info("Successfully run: {}".format(result['cmd']))


@pytest.mark.parametrize('status', ['active', 'inactive'])
@pytest.mark.parametrize('key_type', key_types)
def test_pki_kra_key_mod_modify_key_status_to_same_status(ansible_module, status, key_type):
    """
    :Title: Test pki kra-key-mod Modify status of the key to same status again
    :Description: Test pki kra-key-mod, Modify status of the key to same status again
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki kra-key-generate --key-algorithm AES --key-size 256
        2. pki kra-key-review <request_id> --action rejected
        3. pki kra-key-mod <key_id> --action active
    :ExpectedResults:
        1. Key status should changed to active successfully
    """
    clientid = 'testuser21076_{}'.format(random.randint(1111, 99999999))

    key_size = key_lengths.get(key_type)

    key_id = key_library.generate_key(ansible_module, key_size=key_size, algo=key_type,
                                      client_key_id=clientid, action='approve')

    key_library.modify_key_status(ansible_module, key_id=key_id['request_id'], status=status)

    help_out = ansible_module.pki(cli=pki_cmd,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  port=constants.KRA_HTTP_PORT,
                                  hostname=constants.MASTER_HOSTNAME,
                                  certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                  extra_args='{} --status {}'.format(key_id.get('key_id'), status))
    for result in help_out.values():
        if result['rc'] == 0:
            assert 'Key ID: {}'.format(key_id.get('key_id')) in result['stdout']
            assert 'Client Key ID: {}'.format(clientid) in result['stdout']
            assert 'Status: {}'.format(status) in result['stdout']
            assert 'Algorithm: {}'.format(key_type) in result['stdout']
            assert 'Size: {}'.format(key_size) in result['stdout']
            assert 'Owner: {}'.format(constants.KRA_ADMIN_USERNAME) in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


@pytest.mark.parametrize('status', ['active', 'inactive'])
def test_pki_kra_key_mod_change_status_of_archived_key(ansible_module, status):
    """
    :Title: Test pki kra-key-mod change securityDataEnrollment key status to inactive
    :Description: Test pki kra-key-mod change securityDataEnrollment key status to inactive
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Archive key using pki kra-key-archive
        2. Change the status of the key.
    :ExpectedResults:
        1. Key status should changed successfully.
    """
    clientid = 'testuser21077_{}'.format(random.randint(1111, 99999999))

    key_req_id = key_library.archive_key(ansible_module, client_key_id=clientid,
                                         passphrase=constants.CLIENT_DATABASE_PASSWORD)
    key_id = key_library.review_key_request(ansible_module, key_req_id['request_id'], action='approve')
    log.info("Key Request approved. Key ID: {}".format(key_id))
    help_out = ansible_module.pki(cli=pki_cmd,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  port=constants.KRA_HTTP_PORT,
                                  hostname=constants.MASTER_HOSTNAME,
                                  certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                  extra_args='{} --status {}'.format(key_id, status))
    for result in help_out.values():
        if result['rc'] == 0:
            assert 'Key ID: {}'.format(key_id) in result['stdout']
            assert 'Client Key ID: {}'.format(clientid) in result['stdout']
            assert 'Status: {}'.format(status) in result['stdout']
            assert 'Owner: {}'.format(constants.KRA_ADMIN_USERNAME) in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


@pytest.mark.parametrize('status', ['active', 'inactive'])
def test_pki_kra_key_mod_change_status_of_archived_rejected_key(ansible_module, status):
    """
    :Title: Test pki kra-key-mod change securityDataEnrollment rejected key status to inactive
    :Description: Test pki kra-key-mod change securityDataEnrollment rejected key status to inactive
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Archive key using pki kra-key-archive
        2. Change the status of the key.
    :ExpectedResults:
        1. Key status should changed successfully.
    """
    clientid = 'testuser21078_{}'.format(random.randint(1111, 99999999))

    key_req_id = key_library.archive_key(ansible_module, client_key_id=clientid,
                                         passphrase=constants.CLIENT_DATABASE_PASSWORD)
    key_id = key_library.review_key_request(ansible_module, key_req_id['request_id'], action='reject')
    log.info("Key Request rejected. Key ID: {}".format(key_id))
    help_out = ansible_module.pki(cli=pki_cmd,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  port=constants.KRA_HTTP_PORT,
                                  hostname=constants.MASTER_HOSTNAME,
                                  certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                  extra_args='{} --status {}'.format(key_id, status))
    for result in help_out.values():
        if result['rc'] == 0:
            assert 'Key ID: {}'.format(key_id) in result['stdout']
            assert 'Client Key ID: {}'.format(clientid) in result['stdout']
            assert 'Status: {}'.format(status) in result['stdout']
            assert 'Owner: {}'.format(constants.KRA_ADMIN_USERNAME) in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


@pytest.mark.parametrize('status', ['active', 'inactive'])
def test_pki_kra_key_mod_change_status_of_archived_canceled_key(ansible_module, status):
    """
    :Title: Test pki kra-key-mod change securityDataEnrollment canceled key status to inactive
    :Description: Test pki kra-key-mod change securityDataEnrollment canceled key status to inactive
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Archive key using pki kra-key-archive
        2. Change the status of the key.
    :ExpectedResults:
        1. Key status should changed successfully.
    """
    clientid = 'testuser21079_{}'.format(random.randint(1111, 99999999))

    key_req_id = key_library.archive_key(ansible_module, client_key_id=clientid,
                                         passphrase=constants.CLIENT_DATABASE_PASSWORD)
    key_id = key_library.review_key_request(ansible_module, key_req_id['request_id'], action='cancel')
    log.info("Key Request canceled. Key ID: {}".format(key_id))

    help_out = ansible_module.pki(cli=pki_cmd,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  port=constants.KRA_HTTP_PORT,
                                  hostname=constants.MASTER_HOSTNAME,
                                  certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                  extra_args='{} --status {}'.format(key_id, status))
    for result in help_out.values():
        if result['rc'] == 0:
            assert 'Key ID: {}'.format(key_id) in result['stdout']
            assert 'Client Key ID: {}'.format(clientid) in result['stdout']
            assert 'Status: {}'.format(status) in result['stdout']
            assert 'Owner: {}'.format(constants.KRA_ADMIN_USERNAME) in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


def test_pki_kra_key_mod_change_invalid_status_of_archived_key(ansible_module):
    """
    :Title: Test pki kra-key-mod change securityDataEnrollment canceled key status to invalid
    :Description: Test pki kra-key-mod change securityDataEnrollment canceled key status to invalid
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Archive key using pki kra-key-archive
        2. Change the status of the key.
    :ExpectedResults:
        1. It should throw an error
    """
    status = 'asdfa'
    clientid = 'testuser21080_{}'.format(random.randint(1111, 99999999))

    key_req_id = key_library.archive_key(ansible_module, client_key_id=clientid,
                                         passphrase=constants.CLIENT_DATABASE_PASSWORD)
    key_id = key_library.review_key_request(ansible_module, key_req_id['request_id'], action='approve')
    log.info("Key Request approved. Key ID: {}".format(key_id))
    help_out = ansible_module.pki(cli=pki_cmd,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  port=constants.KRA_HTTP_PORT,
                                  hostname=constants.MASTER_HOSTNAME,
                                  certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                  extra_args='{} --status {}'.format(key_id, status))
    for result in help_out.values():
        if result['rc'] == 0:
            assert 'Key ID: {}'.format(key_id) in result['stdout']
            assert 'Client Key ID: {}'.format(clientid) in result['stdout']
            assert 'Status: {}'.format(status) in result['stdout']
            assert 'Owner: {}'.format(constants.KRA_ADMIN_USERNAME) in result['stdout']
            log.error("Failed to run: {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
        else:
            assert "IllegalArgumentException: Invalid status value." in result['stderr']
            log.info("Successfully run: {}".format(result['cmd']))


@pytest.mark.parametrize('status', ['active', 'inactive'])
def test_pki_kra_key_mod_modify_archived_key_status_to_same_status(ansible_module, status):
    """
    :Title: Test pki kra-key-mod Modify status of the key to same status again
    :Description: Test pki kra-key-mod, Modify status of the key to same status again
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki kra-key-generate --key-algorithm AES --key-size 256
        2. pki kra-key-review <request_id> --action rejected
        3. pki kra-key-mod <key_id> --action active
    :ExpectedResults:
        1. Key status should changed to active successfully
    """
    clientid = 'testuser21081_{}'.format(random.randint(1111, 99999999))

    key_req_id = key_library.archive_key(ansible_module, client_key_id=clientid,
                                         passphrase=constants.CLIENT_DATABASE_PASSWORD)
    key_id = key_library.review_key_request(ansible_module, key_req_id['request_id'], action='approve')
    log.info("Key Request approved. Key ID: {}".format(key_id))
    key_library.modify_key_status(ansible_module, key_id=key_id, status=status)

    help_out = ansible_module.pki(cli=pki_cmd,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  port=constants.KRA_HTTP_PORT,
                                  hostname=constants.MASTER_HOSTNAME,
                                  certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                  extra_args='{} --status {}'.format(key_req_id['key_id'], status))
    for result in help_out.values():
        if result['rc'] == 0:
            assert 'Key ID: {}'.format(key_id) in result['stdout']
            assert 'Client Key ID: {}'.format(clientid) in result['stdout']
            assert 'Status: {}'.format(status) in result['stdout']
            assert 'Owner: {}'.format(constants.KRA_ADMIN_USERNAME) in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


@pytest.mark.parametrize('users', ['KRA_AdminV', 'KRA_AgentV', 'KRA_AuditV'])
def test_pki_kra_key_mod_using_valid_user_cert(ansible_module, users):
    """
    :Title: Test pki kra-key-mod using valid user cert
    :Description: Test pki kra-key-mod using valid user cert
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -n KRA_AdminV kra-key-mod --status inactive
        2. pki -n KRA_AgentV kra-key-mod --status inactive
        3. pki -n KRA_AuditV kra-key-mod --status inactive
    :ExpectedResults:
        1. Key should get mod.
        2. It should throw an error
        3. It should throw an error
    """
    clientID = 'testuser21082_{}'.format(random.randint(11111, 99999999))
    status = 'inactive'
    key_id = key_library.generate_key(ansible_module, key_size=128, algo='AES', client_key_id=clientID,
                                      action='approve')
    generate_key = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.KRA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(users),
                                      extra_args='{} --status {}'.format(key_id['key_id'], status))
    for result in generate_key.values():
        if result['rc'] == 0 and users == 'KRA_AgentV':
            assert 'Key ID: {}'.format(key_id['key_id']) in result['stdout']
            assert 'Client Key ID: {}'.format(clientID) in result['stdout']
            assert 'Status: {}'.format(status) in result['stdout']
            assert 'Owner: {}'.format(constants.KRA_ADMIN_USERNAME) in result['stdout']
            log.info('Successfully run : {}'.format(result['cmd']))
        else:
            assert "ForbiddenException: Authorization Error" in result['stderr']
            log.info('Successfully run : {}'.format(result['cmd']))


@pytest.mark.parametrize('users', ['KRA_AdminR', 'KRA_AuditR', 'KRA_AgentR'])
def test_pki_kra_key_mod_using_revoked_user_cert(ansible_module, users):
    """
    :Title: Test pki kra-key-mod using valid user cert
    :Description: Test pki kra-key-mod using valid user cert
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -n KRA_AdminR kra-key-mod --key-algorithm AES
        2. pki -n KRA_AgentR kra-key-mod --key-algorithm AES
        3. pki -n KRA_AuditR kra-key-mod --key-algorithm AES
    :ExpectedResults:
        1. Key should get modd.
        2. It should throw an error
        3. It should throw an error
    """
    clientID = 'testuser21083_{}'.format(random.randint(11111, 99999999))
    status = 'inactive'
    key_id = key_library.generate_key(ansible_module, key_size=128, algo='AES', client_key_id=clientID,
                                      action='approve')
    generate_key = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.KRA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(users),
                                      extra_args='{} --status {}'.format(key_id['key_id'], status))
    for result in generate_key.values():
        if result['rc'] == 0:
            assert 'Key ID: {}'.format(key_id['key_id']) in result['stdout']
            assert 'Client Key ID: {}'.format(clientID) in result['stdout']
            assert 'Status: {}'.format(status) in result['stdout']
            assert 'Owner: {}'.format(constants.KRA_ADMIN_USERNAME) in result['stdout']
            log.error("Failed to run: {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
        else:
            assert 'FATAL: SSL alert received: CERTIFICATE_REVOKED' in result['stderr']
            log.info('Successfully run : {}'.format(result['cmd']))


@pytest.mark.parametrize('users', ['KRA_AdminE', 'KRA_AgentE', 'KRA_AuditE'])
def test_pki_kra_key_mod_using_expired_user_cert(ansible_module, users):
    """
    :Title: Test pki kra-key-mod using expired user cert
    :Description: Test pki kra-key-mod using expired user cert
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -n KRA_AdminE kra-key-mod --key-algorithm AES
        2. pki -n KRA_AgentE kra-key-mod --key-algorithm AES
        3. pki -n KRA_AuditE kra-key-mod --key-algorithm AES
    :ExpectedResults:
        1. Key should get modd.
        2. It should throw an error
        3. It should throw an error
    """
    clientID = 'testuser21084_{}'.format(random.randint(11111, 99999999))
    status = 'inactive'
    key_id = key_library.generate_key(ansible_module, key_size=128, algo='AES', client_key_id=clientID,
                                      action='approve')
    generate_key = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.KRA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(users),
                                      extra_args='{} --status {}'.format(key_id, status))
    for result in generate_key.values():
        if result['rc'] == 0:
            assert 'Key ID: {}'.format(key_id) in result['stdout']
            assert 'Client Key ID: {}'.format(clientID) in result['stdout']
            assert 'Status: {}'.format(status) in result['stdout']
            assert 'Owner: {}'.format(constants.KRA_ADMIN_USERNAME) in result['stdout']
            log.error("Failed to run: {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
        else:
            if 'CERTIFICATE_EXPIRED' in result['stderr']:
                error = 'FATAL: SSL alert received: CERTIFICATE_EXPIRED\n' \
                        'IOException: SocketException cannot write on socket' in result['stderr']
            elif 'IOException' in result['stderr']:
                assert 'IOException: SocketException cannot write on socket' in result['stderr']
            else:
                error = "ATAL: SSL alert received: CERTIFICATE_UNKNOWN\n" \
                        "IOException: SocketException cannot write on socket"
                assert error in result['stderr']
            log.info('Successfully run : {}'.format(result['cmd']))


def test_pki_kra_key_mod_with_user_who_is_not_member_of_any_group(ansible_module):
    """
    :Title: KRA key-mod using user who is not member of any group
    :Description: KRA Key-mod using user who is not member of any group
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Add user.
        2. Issue certificate to user, add certificate to user
        3. Import certificate to client db and generate key using cert.
    :ExpectedResults:
        1. It should throw an exception.
    """
    clientID = 'testuser21085_{}'.format(random.randint(11111, 99999999))

    userid = "testuser21086_{}".format(random.randint(11111, 99999999))
    fullName = "Test {}".format(userid)
    subject = "UID={},CN={}".format(userid, fullName)
    cert_file = "/tmp/{}.pem".format(userid)
    userop.add_user(ansible_module, 'add', userid=userid, user_name=fullName, subsystem='kra')
    log.info("Added user {}".format(userid))
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 request_type='pkcs10', algo='rsa',
                                                 keysize=2048, profile='caUserCert')
    log.info("Created certificate with Cert ID: {}".format(cert_id))
    if cert_id:
        imported = ansible_module.command(basic_pki_cmd_ca + ' client-cert-import {} '
                                                             '--serial {}'.format(userid, cert_id))
        for result in imported.values():
            assert result['rc'] == 0
            log.info("Imported certificate to certdb.")
        exported = ansible_module.command(basic_pki_cmd_ca + ' ca-cert-show {} --output {}'.format(cert_id, cert_file))
        for result in exported.values():
            assert result['rc'] == 0
            log.info("Stored certificate to the file.")
        cert_add = ansible_module.pki(cli='kra-user-cert-add',
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.KRA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                      extra_args='{} --input {}'.format(userid, cert_file))
        for result in cert_add.values():
            if result['rc'] == 0:
                assert 'Added certificate' in result['stdout']

                log.info("Added certificate to the user.")
            else:
                log.error("Failed to add certificate to the user.")
                log.info(result['stdout'])
                log.error(result['stderr'])
                pytest.fail()
    status = 'inactive'
    key_id = key_library.generate_key(ansible_module, key_size=128, algo='AES', client_key_id=clientID,
                                      action='approve')
    generate_key = ansible_module.pki(cli=pki_cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.KRA_HTTP_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      certnick='"{}"'.format(userid),
                                      extra_args='"{}" --status {}'.format(key_id['key_id'], status))
    for result in generate_key.values():
        if result['rc'] == 0:
            assert 'Key ID: {}'.format(key_id) in result['stdout']
            assert 'Client Key ID: {}'.format(clientID) in result['stdout']
            assert 'Status: {}'.format(status) in result['stdout']
            assert 'Owner: {}'.format(constants.KRA_ADMIN_USERNAME) in result['stdout']
            log.error("Failed to run: {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
        else:
            assert "ForbiddenException: Authorization Error" in result['stderr']
            log.info('Successfully run : {}'.format(result['cmd']))

    ansible_module.command('rm -rf {}'.format(cert_file))
    userop.remove_user(ansible_module, userid)
    ansible_module.command(basic_pki_cmd_ca + ' client-cert-del {}'.format(userid))


def test_pki_kra_key_mod_using_https_uri(ansible_module):
    """
    :Title: Test pki kra-key-mod using https uri
    :Description: Test pki kra-key-mod using https uri
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki kra-key-generate --key-algorithm AES --key-size 256
        2. pki kra-key-review <request_id> --action rejected
        3. pki -U https://pki1.example.com:8443 kra-key-mod <key_id> --action active
    :ExpectedResults:
        1. Key status should changed to active successfully
    """
    status = 'inactive'
    clientid = 'testuser21087_{}'.format(random.randint(1111, 99999999))

    key_req_id = key_library.archive_key(ansible_module, client_key_id=clientid,
                                         passphrase=constants.CLIENT_DATABASE_PASSWORD)
    key_id = key_library.review_key_request(ansible_module, key_req_id['request_id'], action='approve')
    log.info("Key Request approved. Key ID: {}".format(key_id))
    key_library.modify_key_status(ansible_module, key_id=key_id, status=status)

    help_out = ansible_module.pki(cli=pki_cmd,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  port=constants.KRA_HTTPS_PORT,
                                  protocol='https',
                                  hostname=constants.MASTER_HOSTNAME,
                                  certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                  extra_args='{} --status {}'.format(key_id, status))
    for result in help_out.values():
        if result['rc'] == 0:
            assert 'Key ID: {}'.format(key_id) in result['stdout']
            assert 'Client Key ID: {}'.format(clientid) in result['stdout']
            assert 'Status: {}'.format(status) in result['stdout']
            assert 'Owner: {}'.format(constants.KRA_ADMIN_USERNAME) in result['stdout']
            log.info("Successfully run: {}".format(result['cmd']))
        else:
            log.error("Failed to run: {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


def test_pki_kra_key_mod_using_invalid_user(ansible_module):
    """
    :Title: Test pki kra-key-mod using invalid user
    :Description: Test pki kra-key-mod using invalid user
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki kra-key-generate --key-algorithm AES --key-size 256
        2. pki kra-key-review <request_id> --action rejected
        3. pki -u invalid -w invalid kra-key-mod <key_id> --action active
    :ExpectedResults:
        1. It should not modify the key status
    """
    status = 'inactive'
    clientid = 'testuser21088_{}'.format(random.randint(1111, 99999999))

    key_req_id = key_library.archive_key(ansible_module, client_key_id=clientid,
                                         passphrase=constants.CLIENT_DATABASE_PASSWORD)
    key_id = key_library.review_key_request(ansible_module, key_req_id['request_id'], action='approve')
    log.info("Key Request approved. Key ID: {}".format(key_id))
    key_library.modify_key_status(ansible_module, key_id=key_id, status=status)

    help_out = ansible_module.pki(cli=pki_cmd,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  port=constants.KRA_HTTPS_PORT,
                                  protocol='https',
                                  authType='basicAuth',
                                  username='testuser',
                                  userpassword='SECret.123',
                                  hostname=constants.MASTER_HOSTNAME,
                                  extra_args='{} --status {}'.format(key_id, status))
    for result in help_out.values():
        if result['rc'] == 0:
            assert 'Key ID: {}'.format(key_id) in result['stdout']
            assert 'Client Key ID: {}'.format(clientid) in result['stdout']
            assert 'Status: {}'.format(status) in result['stdout']
            assert 'Owner: {}'.format(constants.KRA_ADMIN_USERNAME) in result['stdout']
            log.error("Failed to run: {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
        else:
            log.info("Successfully run: {}".format(result['cmd']))
