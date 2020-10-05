#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI KRA KEY CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following kra-key-find cli commands needs to be tested:
#   pki kra-key-find
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Akshay Adhikari <aadhikar@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2017 Red Hat, Inc. All rights reserved.
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
import sys

import pytest

sys.path.insert(0, '.')
from utils import *
import random

if os.path.isfile('/tmp/test_dir/constants.py'):
    sys.path.append('/tmp/test_dir')
    import constants

global key_library
key_library = pki_key_library(nssdb='/opt/rhqa_pki/certdb',
                              db_pass=constants.CLIENT_DATABASE_PASSWORD,
                              host='pki1.exmaple.com',
                              port=constants.KRA_HTTP_PORT,
                              nick="'{}'".format(constants.KRA_ADMIN_NICK))
global generate_cert
generate_cert = pki_generate_cert_library(nssdb='/opt/rhqa_pki/certdb',
                              db_pass=constants.CLIENT_DATABASE_PASSWORD,
                              host='pki1.exmaple.com',
                              port=constants.KRA_HTTP_PORT,
                              nick="'{}'".format(constants.KRA_ADMIN_NICK))

junk_val = os.popen("openssl rand -base64 50 |  perl -p -e 's/\n//'").read()
random_val = 'tuser%s' % random.randint(1111, 99999999)


@pytest.mark.parametrize("subcmd,expected", [('--help', ['usage: kra-key-find [OPTIONS...]',
                                                         ' --clientKeyID <client key ID>   Unique client key identifier',
                                                         '--help                          Show help options',
                                                         '--maxResults <max results>      Maximum results',
                                                         '--maxTime <max time>            Maximum time',
                                                         '--realm <realm>                 Realm',
                                                         '--size <size>                   Page size',
                                                         '--start <start>                 Page start',
                                                         '--status <status>               Status']),
                                             ('', 'Number of entries returned')
                                             ])
@pytest.mark.parametrize('protocol', ('https', 'http'))
def test_pki_kra_find_help(ansible_module, protocol, subcmd, expected):
    """
    :id: edffcdab-c860-47dc-9ff4-746ce7742e84

    :Title: RHCS-TC Test pki kra-key-find with '' and '--help'

    :Test: Test pki kra-key-find command with '' and '--help'

    :Description:
        This command will test the pki kra-key-find with '' and '--help' option,
        for '' option it is expected to show the keys form the database, and
        for '--help' it should show the help message.

    :Requirement: pki kra-key-find

    :CaseComponent: \-

    :Type:

    :Steps:
            1. pki kra-key-find
            2. pki kra-key-find --help

    :ExpectedResults:
            1. It should shows the kra keys form the database
            2. --help option should shows the help message.
    """
    output = ansible_module.pki(
        cli='kra-key-find',
        protocol=protocol,
        certnick="'{}'".format(constants.KRA_ADMIN_NICK),
        extra_args='{}'.format(subcmd))
    for (result) in output.values():
        for iter in expected:
            assert iter in result['stdout']


# test_pki_kra_find_with_valid_clientID
@pytest.mark.parametrize('protocol', ('https', 'http'))
def test_pki_kra_find_with_valid_clientID(ansible_module, protocol):
    """
    :id: 940e50a9-95d2-4f39-bb5d-29efd50f2dbc

    :Title: RHCS-TC Test pki kra-key-find with valid id passed to '--clientKeyID'

    :Test: Test pki kra-key-find with '--clientKeyID'

    :Description:
             This command will test the pki kra-key-find with '--clientKeyID' option,
             it is expected to show the key associated with the client ID's value.

    :Requirement: pki kra-key-find

    :CaseComponent: \-

    :Type:

    :Steps:
            1. pki kra-key-find --clientKeyID <client key ID>

    :ExpectedResults:
            1. It should show the kra key with the associated client key ID.
    """
    clientID_random = 'tuser%s' % random.randint(1111, 99999999)
    key_id = key_library.generate_key(ansible_module, algo='RSA',
                                      key_size='2048', usages='wrap,unwrap', client_key_id=clientID_random)
    output = ansible_module.pki(cli='kra-key-find',
                                protocol=protocol,
                                certnick="'{}'".format(constants.KRA_ADMIN_NICK),
                                extra_args='--clientKeyID {}'.format(clientID_random))
    for result in output.values():
        assert "Key ID: {}".format(key_id) in result['stdout']
        assert "Client Key ID: {}".format(clientID_random) in result['stdout']
        assert "Status: active" in result['stdout']
        assert "Algorithm: RSA" in result['stdout']
        assert "Owner: {}".format(constants.KRA_ADMIN_USERNAME) in result['stdout']


# test_pki_kra_find_with_junkdata/Invalid_passed_to_clientID
@pytest.mark.parametrize('clientID,expected', [(junk_val, ['Number of entries returned 0']),
                                               (random_val, ['Number of entries returned 0'])])
@pytest.mark.parametrize('protocol', ('https', 'http'))
@pytest.mark.positive
def test_pki_kra_find_with_different_value_passed_to_clientID(ansible_module, protocol,
                                                              expected, clientID):
    """
    :id: 742c6777-bf87-4ad7-ba35-a3376f6d4b1d

    :Title: RHCS-TC Test pki kra-key-find with different value passed to '--clientKeyID'

    :Test: Test pki kra-key-find with different value passed to '--clientKeyID'

    :Description:
            This command will test the pki kra-key-find with junk/random '--clientKeyID' options,
             it is expected to show the number of entries as 0 .

    :Requirement: pki kra-key-find

    :CaseComponent: \-

    :Type:

    :Steps:
            1. pki kra-key-find --clientKeyID <junk>
            2. pki kra-key-find --clientKeyID <random>

    :ExpectedResults:
            1. junk/random option in results should show the number of entries as 0 .
    """
    output = ansible_module.pki(cli='kra-key-find',
                                protocol=protocol,
                                certnick="'{}'".format(constants.KRA_ADMIN_NICK),
                                extra_args='--clientKeyID {}'.format(clientID))
    for (result) in output.values():
        assert result['rc'] == 0
        for iter in expected:
            assert iter in result['stdout']


# test_pki_kra_find_without_data_to_clientID
@pytest.mark.parametrize('clientID,expected',
                         [('',['MissingArgumentException: Missing argument for option: clientKeyID']),
                          ])
@pytest.mark.parametrize('protocol', ('https', 'http'))
@pytest.mark.negative
def test_pki_kra_find_without_data_to_clientID(ansible_module, protocol,
                                               expected, clientID):
    """
    :id: 4bcac520-f912-4682-8f21-17f6ca3a24e1

    :Title: RHCS-TC Test pki kra-key-find with no value passed to '--clientKeyID'

    :Test: Test pki kra-key-find with no value passed to '--clientKeyID'

    :Description:
            This command will test the pki kra-key-find with no data passed to '--clientKeyID' options,
            it is expected to give error as stating Missing argument for the option i.e clientKeyID

    :Requirement: pki kra-key-find

    :CaseComponent: \-

    :Type:

    :Steps:
            1. pki kra-key-find --clientKeyID

    :ExpectedResults:
            1. It is expected to give error as stating Missing argument for the option i.e clientKeyID
    """
    output = ansible_module.pki(cli='kra-key-find',
                                protocol=protocol,
                                certnick="'{}'".format(constants.KRA_ADMIN_NICK),
                                extra_args='--clientKeyID {}'.format(clientID))
    for (result) in output.values():
        assert result['rc'] != 0
        for iter in expected:
            assert iter in result['stderr']


# test_pki_kra_find_with_maxResult_value
@pytest.mark.parametrize('maxResults,expected', [('5',['Number of entries returned 5'])])
@pytest.mark.parametrize('protocol', ('https', 'http'))
@pytest.mark.positive
def test_pki_kra_find_with_maxResult_value(ansible_module, protocol,
                                           maxResults, expected):
    """
    :id: f5d27204-540e-4951-b11e-3368d0fc3ac2

    :Title: RHCS-TC Test pki kra-key-find with valid value passed to '--maxResults'

    :Test: Test pki kra-key-find with '--maxResults'

    :Description:
             This command will test the pki kra-key-find with '--maxResults' option,
             it is expected to show the key associated with the maxResult's value.

    :Requirement: pki kra-key-find

    :CaseComponent: \-

    :Type:

    :Steps:
            1. pki kra-key-find --maxResults <max results>

    :ExpectedResults:
            1. It should result in number of entries returned as 5 .
    """
    for x in range(1, 6):
        user = 'tuser%s' % random.randint(1111, 99999999)
        key_library.generate_key(ansible_module, algo='RSA',
                                 key_size='2048', usages='wrap,unwrap', client_key_id=user)
    output = ansible_module.pki(cli='kra-key-find',
                                protocol=protocol,
                                certnick="'{}'".format(constants.KRA_ADMIN_NICK),
                                extra_args='--maxResults {}'.format(maxResults))
    for (result) in output.values():
        assert result['rc'] == 0
        for iter in expected:
            assert iter in result['stdout']


# test_pki_kra_find_with_differnt_maxResult_value
@pytest.mark.parametrize('maxResults,expected', [(junk_val, ['NumberFormatException: For input string:']),
                                                 ('1234567890123', ['NumberFormatException: For input string:']),
                                                 ('', ['MissingArgumentException: Missing argument for '
                                                      'option: maxResults']),
                                                 pytest.mark.xfail(('-128',['NumberFormatException: For input string:']))
                                                ])
@pytest.mark.parametrize('protocol', ('https', 'http'))
@pytest.mark.negative
def test_pki_kra_find_with_different_maxResult_value(ansible_module, protocol,
                                                     maxResults, expected):
    """
    :id: c85bb252-6528-4d67-b018-3e80a2464f90

    :Title: RHCS-TC Test pki kra-key-find with different value passed to '--maxResults'

    :Test: Test pki kra-key-find with different value passed to '--maxResults'

    :Description:
            This command will test the pki kra-key-find with junk/12-digit/blank/negative '--maxResults' options,
             it is expected to result in NumberFormatException for all options and Missing argument for ''.

    :Requirement: pki kra-key-find

    :CaseComponent: \-

    :Type:

    :Steps:
            1. pki kra-key-find --maxResults <junk>
            2. pki kra-key-find --maxResults <more than 10-digit number>
            3. pki kra-key-find --maxResults
            4. pki kra-key-find --maxResults <negative_value>

    :ExpectedResults:
            1. junk/12-digit/negative option in result should give NumberFormatException.
            2. blank option should result in Missing argument .
    """
    output = ansible_module.pki(cli='kra-key-find',
                                protocol=protocol,
                                certnick="'{}'".format(constants.KRA_ADMIN_NICK),
                                extra_args='--maxResults {}'.format(maxResults))
    for (result) in output.values():
        if result['rc'] == 0:
            print("PKI TICKET:: https://fedorahosted.org/pki/ticket/1121")
            print("RH BZ:: https://bugzilla.redhat.com/show_bug.cgi?id=1239068")
            pytest.xfail("Failed to run pki kra-key-find --maxResults {}".format(maxResults))
        else:
            for iter in expected:
                assert iter in result['stderr']


# test_pki_kra_find_with_size_value
@pytest.mark.parametrize('size,expected', [('5',['Number of entries returned 5'])])
@pytest.mark.parametrize('protocol', ('https', 'http'))
@pytest.mark.positive
def test_pki_kra_find_with_size_value(ansible_module, protocol,
                                      size, expected):
    """
    :id: ebbf8fc1-be71-4028-bf76-3cbff479f313

    :Title: RHCS-TC Test pki kra-key-find with valid value passed to '--size'

    :Test: Test pki kra-key-find with '--size'

    :Description:
             This command will test the pki kra-key-find with '--size' option,
             it is expected to show the key associated with the size's value.

    :Requirement: pki kra-key-find

    :CaseComponent: \-

    :Type:

    :Steps:
            1. pki kra-key-find --size <size>

    :ExpectedResults:
            1. It should result in number of entries returned as 5 .
    """
    output = ansible_module.pki(cli='kra-key-find',
                                protocol=protocol,
                                certnick="'{}'".format(constants.KRA_ADMIN_NICK),
                                extra_args='--size {}'.format(size))
    for (result) in output.values():
        assert result['rc'] == 0
        for iter in expected:
            assert iter in result['stdout']


# test_pki_kra_find_with_different_size_value
@pytest.mark.parametrize('size,expected', [(junk_val, ['NumberFormatException: For input string:']),
                                           ('1234567890123', ['NumberFormatException: For input string:']),
                                           ('', ['MissingArgumentException: Missing argument for option: size']),
                                           pytest.mark.xfail(('-128', ['NumberFormatException: For input string:']))
                                           ])
@pytest.mark.parametrize('protocol', ('https', 'http'))
@pytest.mark.negetive
def test_pki_kra_find_with_different_size_value(ansible_module, protocol, size, expected):
    """
    :id: 9dea5086-8462-4c7d-a17a-bc0ce37ba88a

    :Title: RHCS-TC Test pki kra-key-find with different value passed to '--size'

    :Test: Test pki kra-key-find with different value passed to '--size'

    :Description:
            This command will test the pki kra-key-find with junk/12-digit/blank/negative '--size' options,
             it is expected to result in NumberFormatException for all options and Missing argument for ''.

    :Requirement: pki kra-key-find

    :CaseComponent: \-

    :Type:

    :Steps:
            1. pki kra-key-find --size <junk>
            2. pki kra-key-find --size <more than 10-digit number>
            3. pki kra-key-find --size
            4. pki kra-key-find --size <negative_value>

    :ExpectedResults:
            1. Junk/12-digit/negative option in result should give NumberFormatException.
            2. Blank option should result in Missing argument .
    """
    output = ansible_module.pki(
        cli='kra-key-find',
        protocol=protocol,
        certnick="'{}'".format(constants.KRA_ADMIN_NICK),
        extra_args='--size {}'.format(size))
    for (result) in output.values():
        if result['rc'] == 0:
            print("RH BZ:: https://bugzilla.redhat.com/show_bug.cgi?id=1239068")
            pytest.xfail("Failed to run pki kra-key-find --size {}".format(size))
        else:
            for iter in expected:
                assert iter in result['stderr']


# test_pki_kra_find_with_key_status_active
@pytest.mark.parametrize('protocol', ('https', 'http'))
@pytest.mark.positive
def test_pki_kra_find_with_key_status_active(ansible_module, protocol):
    """
    :id: a4436427-bb32-4830-92c8-00cbbdbaa6dd

    :Title: RHCS-TC Test pki kra-key-find with active value passed to '--status'

    :Test: Test pki kra-key-find with active value passed to '--status'

    :Description:
            This command will test the pki kra-key-find with active value passed to --status and
            1000 value passed to --maxResults and --size.

    :Requirement: pki kra-key-find

    :CaseComponent: \-

    :Type:

    :Steps:
            1. pki kra-key-find --status active --maxResults 1000 --size 1000


    :ExpectedResults:
            1. The status of the keys listed should be active.

    """
    status = 'active'
    clientID_random = 'tuser%s' % random.randint(1111, 99999999)
    key_id = key_library.generate_key(ansible_module, algo='RSA',
                                      key_size='2048', usages='wrap,unwrap', client_key_id=clientID_random)
    output = ansible_module.pki(cli='kra-key-find',
                                protocol=protocol,
                                certnick="'{}'".format(constants.KRA_ADMIN_NICK),
                                extra_args='--status {} --maxResults {} --size {}'.format(status, 1000, 1000))
    for (result) in output.values():
        assert "Key ID: {}".format(key_id) in result['stdout']
        assert "Client Key ID: {}".format(clientID_random) in result['stdout']
        assert "Status: active" in result['stdout'], "Result contain inactive Keys"
        assert "Algorithm: RSA" in result['stdout']
        assert "Owner: {}".format(constants.KRA_ADMIN_USERNAME) in result['stdout']


# test_pki_kra_find_with_key_status_inactive
@pytest.mark.parametrize('protocol', ('https', 'http'))
@pytest.mark.positive
def test_pki_kra_find_with_key_status_inactive(ansible_module, protocol):
    """
    :id: a198558c-89f0-4532-aaf5-527857c7f151

    :Title: RHCS-TC Test pki kra-key-find with inactive value passed to '--status'

    :Test: Test pki kra-key-find with inactive value passed to '--status'

    :Description:
            This command will test the pki kra-key-find with inactive value passed to --status and
            1000 value passed to --maxResults and --size.

    :Requirement: pki kra-key-find

    :CaseComponent: \-

    :Type:

    :Steps:
            1. pki kra-key-mod <client key ID> --status inactive
            2. pki kra-key-find --status inactive --maxResults 1000 --size 1000


    :ExpectedResults:
            1. The status of the keys listed should be active.

    """
    status = 'inactive'
    clientID_random = 'tuser%s' % random.randint(1111, 99999999)
    key_id = key_library.generate_key(ansible_module, algo='RSA',
                                      key_size='2048', usages='wrap,unwrap', client_key_id=clientID_random)
    input = ansible_module.pki(cli='kra-key-mod',
                               protocol=protocol,
                               certnick="'{}'".format(constants.KRA_ADMIN_NICK),
                               extra_args='{} --status {}'.format(key_id, status))
    for (result) in input.values():
        assert "Key ID: {}".format(key_id) in result['stdout']
        assert "Client Key ID: {}".format(clientID_random) in result['stdout']
        assert "Status: inactive" in result['stdout']
        assert "Algorithm: RSA" in result['stdout']
        assert "Owner: {}".format(constants.KRA_ADMIN_USERNAME) in result['stdout']
    output = ansible_module.pki(cli='kra-key-find',
                                protocol=protocol,
                                certnick="'{}'".format(constants.KRA_ADMIN_NICK),
                                extra_args='--status {} --maxResults {} '
                                           '--size {}'.format(status, 1000, 1000))
    for (result) in output.values():
        assert "Key ID: {}".format(key_id) in result['stdout']
        assert "Client Key ID: {}".format(clientID_random) in result['stdout']
        assert "Status: inactive" in result['stdout'], "Result contain active Keys"
        assert "Algorithm: RSA" in result['stdout']
        assert "Owner: {}".format(constants.KRA_ADMIN_USERNAME) in result['stdout']


# test_pki_kra_find_with_invalid_key_status
@pytest.mark.parametrize('protocol', ('https', 'http'))
@pytest.mark.positive
def test_pki_kra_find_with_invalid_key_status(ansible_module, protocol):
    """
    :id: bd3196c5-9d1a-43a4-9474-c1ae87af50db

    :Title: RHCS-TC Test pki kra-key-find with invalid value passed to '--status'

    :Test: Test pki kra-key-find with invalid value passed to '--status'

    :Description:
            This command will test the pki kra-key-find with invalid value passed to --status and
            100 value passed to --size.

    :Requirement: pki kra-key-find

    :CaseComponent: \-

    :Type:

    :Steps:
           1. pki kra-key-find --status <junk> --size 100


    :ExpectedResults:
            1. Junk value should result in Number of entries returned 0.

    """
    status = os.popen("openssl rand -base64 50 |  perl -p -e 's/\n//'").read()
    output = ansible_module.pki(cli='kra-key-find',
                                protocol=protocol,
                                certnick="'{}'".format(constants.KRA_ADMIN_NICK),
                                extra_args='--status {} --size {}'.format(status, 100))
    for (result) in output.values():
        if result['rc'] == 0:
            assert "Number of entries returned 0" in result['stdout']


# test_pki_kra_find_with_blank_key_status
@pytest.mark.parametrize('status,expected', [('', ['MissingArgumentException: Missing argument for option: status'])])
@pytest.mark.parametrize('protocol', ('https', 'http'))
@pytest.mark.negative
def test_pki_kra_find_with_blank_key_status(ansible_module, protocol,
                                            expected, status):
    """
    :id: 493a85bb-078e-4dca-9779-a4acd8ab0cdd

    :Title: RHCS-TC Test pki kra-key-find with '' value passed to '--status'

    :Test: Test pki kra-key-find with '' value passed to '--status'

    :Description:
            This command will test the pki kra-key-find with '' value passed to --status and
            100 value passed to --size.

    :Requirement: pki kra-key-find

    :CaseComponent: \-

    :Type:

    :Steps:
           1. pki kra-key-find --status  --size 100


    :ExpectedResults:
            1. Blank value should result in Missing argument for option.

    """
    output = ansible_module.pki(cli='kra-key-find',
                                protocol=protocol,
                                certnick="'{}'".format(constants.KRA_ADMIN_NICK),
                                extra_args='--status {} --size {}'.format(status, 100))
    for (result) in output.values():
        assert result['rc'] != 0
        for iter in expected:
            assert iter in result['stderr']


# test_pki_kra_find_with_key_start_from_0x6_or_negative_value
@pytest.mark.parametrize('start,expected', [('5', ['Key ID: 0x6']),
                                            ('-128', ['Number of entries returned 0'])])
@pytest.mark.parametrize('protocol', ('http', 'https'))
@pytest.mark.positive
def test_pki_kra_find_with_key_start_from_0x6_or_negative_value(ansible_module, protocol,
                                                                expected, start):
    """
    :id: 67e566f2-c4c6-4f4e-a8c2-a80311cb9abe

    :Title: RHCS-TC Test pki kra-key-find with positive and negative value passed to '--start'

    :Test: Test pki kra-key-find with '' value passed to '--start'

    :Description:
            This command will test the pki kra-key-find with positive and negative value passed to --start

    :Requirement: pki kra-key-find

    :CaseComponent: \-

    :Type:

    :Steps:
           1. pki kra-key-find --start 5
           2. pki kra-key-find --start -128


    :ExpectedResults:
            1. Positive value should result in listing keys starting from Key ID:0x6.
            2. Negative value should result in Number of entries returned 0.

    """
    output = ansible_module.pki(cli='kra-key-find',
                                protocol=protocol,
                                certnick="'{}'".format(constants.KRA_ADMIN_NICK),
                                extra_args='--start {}'.format(start))
    for (result) in output.values():
        assert result['rc'] == 0
        for iter in expected:
            assert iter in result['stdout']


# test_pki_kra_find_with_key_start_from_0x6_with_10result
@pytest.mark.parametrize('start,size,expected', [('5', '10', ['Key ID: 0x6', 'Number of entries returned 10'])
                                                 ])
@pytest.mark.parametrize('protocol', ('http', 'https'))
@pytest.mark.positive
def test_pki_kra_find_with_key_start_from_0x6_with_10result(ansible_module, protocol,
                                                            expected, start, size):
    """
    :id: adcec86b-9f79-4a07-a9d5-da423626de37

    :Title: RHCS-TC Test pki kra-key-find with start and size values are passed to '--start' and '--size'
            respectively.

    :Test: Test pki kra-key-find with start and size values are passed to '--start' and '--size'
           respectively.


    :Description:
            This command will test the pki kra-key-find with 5 and 10 value passed to --start and --size
            respectively.

    :Requirement: pki kra-key-find

    :CaseComponent: \-

    :Type:

    :Steps:
           1. pki kra-key-find --start 5 --size 10

    :ExpectedResults:
            1. Positive value should result in listing keys starting from Key ID:0x6 and number of entries
               returned as 10.

    """
    output = ansible_module.pki(cli='kra-key-find',
                                protocol=protocol,
                                certnick="'{}'".format(constants.KRA_ADMIN_NICK),
                                extra_args='--start {} --size {}'.format(start, size))
    for (result) in output.values():
        assert result['rc'] == 0
        for iter in expected:
            assert iter in result['stdout']


# test_pki_kra_find_with_blank_start_value
@pytest.mark.parametrize('start,expected', [('', ['MissingArgumentException: Missing argument for option: start'])])
@pytest.mark.parametrize('protocol', ('https', 'http'))
@pytest.mark.negative
def test_pki_kra_find_with_blank_start_value(ansible_module, protocol,
                                             expected, start):
    """
    :id: d2d45ac4-1edf-4253-ae26-bbdac8a0e98d

    :Title: RHCS-TC Test pki kra-key-find with start and '' values are passed to '--start'

    :Test: Test pki kra-key-find with start and '' values are passed to '--start'


    :Description:
            This command will test the pki kra-key-find with blank value passed to --start
            respectively.

    :Requirement: pki kra-key-find

    :CaseComponent: \-

    :Type:

    :Steps:
           1. pki kra-key-find --start

    :ExpectedResults:
            1. Blank value should result in Missing argument for option.

    """
    output = ansible_module.pki(cli='kra-key-find',
                                protocol=protocol,
                                certnick="'{}'".format(constants.KRA_ADMIN_NICK),
                                extra_args='--start {}'.format(start))
    for (result) in output.values():
        assert result['rc'] != 0
        for iter in expected:
            assert iter in result['stderr']


# test_pki_kra_find_with_maxResult_and_size_value
@pytest.mark.parametrize('maxResults,size,expected', [('105', '105', ['Number of entries returned 105'])])
@pytest.mark.parametrize('protocol', ('https', 'http'))
@pytest.mark.positive
def test_pki_kra_find_with_maxResult_and_size_value(ansible_module, protocol,
                                                    maxResults, size, expected):
    """
    :id: 218857dd-8937-456a-a37f-9ef6c78cbf1a

    :Title: RHCS-TC Test pki kra-key-find with maxResults and size values are passed to '--maxResults'
            and '--size' respectively.

    :Test: Test pki kra-key-find with maxResults and size values are passed to '--maxResults' and '--size'
           respectively.


    :Description:
            This command will test the pki kra-key-find with 105 and 105 value passed to --maxResults
            and --size respectively.

    :Requirement: pki kra-key-find

    :CaseComponent: \-

    :Type:

    :Steps:
           1. pki kra-key-find --maxResults 105 --size 105

    :ExpectedResults:
            1. When 105 as values are passed, it should return result as in Number of entries returned 105.

    """
    for x in range(1, 105):
        user = 'tuser%s' % random.randint(1111, 99999999)
        key_library.generate_key(ansible_module, algo='RSA',
                                 key_size='2048', usages='wrap,unwrap', client_key_id=user)
    output = ansible_module.pki(cli='kra-key-find',
                                protocol=protocol,
                                certnick="'{}'".format(constants.KRA_ADMIN_NICK),
                                extra_args='--maxResults {} --size {}'.format(maxResults, size))
    for (result) in output.values():
        assert result['rc'] == 0
        for iter in expected:
            assert iter in result['stdout']


# test_pki_kra_find_with_size_and_maxResults_value
@pytest.mark.parametrize('size,maxResults,expected', [('105', '105', ['Number of entries returned 105'])])
@pytest.mark.parametrize('protocol', ('https', 'http'))
@pytest.mark.positive
def test_pki_kra_find_with_size_and_maxResults_value(ansible_module, protocol,
                                                     maxResults, size, expected):
    """
    :id: 532c84c2-2c7a-482c-82c4-89651cb2fea2

    :Title: RHCS-TC Test pki kra-key-find with size and maxResults values are passed to '--size'
            and '--maxResults' respectively.

    :Test: Test pki kra-key-find with size and maxResults values are passed to '--size'
            and '--maxResults' respectively.


    :Description:
            This command will test the pki kra-key-find with 105 and 105 value passed to --size
            and --maxResults respectively.

    :Requirement: pki kra-key-find

    :CaseComponent: \-

    :Type:

    :Steps:
           1. pki kra-key-find --size 105 --maxResults 105

    :ExpectedResults:
            1. When 105 as values are passed, it should return result as in Number of entries returned 105.

    """
    output = ansible_module.pki(cli='kra-key-find',
                                protocol=protocol,
                                certnick="'{}'".format(constants.KRA_ADMIN_NICK),
                                extra_args='--size {} --maxResults {}'.format(size, maxResults))
    for (result) in output.values():
        assert result['rc'] == 0
        for iter in expected:
            assert iter in result['stdout']


# test_pki_kra_find_with_maxTime_value
@pytest.mark.parametrize('size,maxTime,expected', [('10', '5', ['Number of entries returned 10']),
                                                   ('10',junk_val, ['NumberFormatException: For input string:'])])
@pytest.mark.parametrize('protocol', ('https', 'http'))
@pytest.mark.positive
def test_pki_kra_find_with_maxTime_value(ansible_module, protocol,
                                         maxTime, size, expected):
    """
    :id: 71bc544a-d155-4991-b3b4-deb89dc5b800

    :Title: RHCS-TC Test pki kra-key-find with size and maxTime values are passed to '--size'
            and '--maxTime' respectively.

    :Test: Test pki kra-key-find with size and maxResults values are passed to '--size'
            and '--maxTime' respectively.


    :Description:
            This command will test the pki kra-key-find with 10 and 5/junk value passed to --size
            and --maxTime respectively.

    :Requirement: pki kra-key-find

    :CaseComponent: \-

    :Type:

    :Steps:
           1. pki kra-key-find --size 10 --maxTime 5
           2. pki kra-key-find --size 10 --maxTime <junk>

    :ExpectedResults:
            1. When value are passed, it should return result as in Number of entries returned 10.
            2. When junk value is passed with maxTime, it should result in NumberFormatException.

    """
    output = ansible_module.pki(cli='kra-key-find',
                                protocol=protocol,
                                certnick="'{}'".format(constants.KRA_ADMIN_NICK),
                                extra_args='--maxTime {} --size {}'.format(maxTime, size))
    for (result) in output.values():
        if result['rc'] == 0:
            for iter in expected:
                assert iter in result['stdout']
        else:
            for iter in expected:
                assert iter in result['stderr']


# test_pki_kra_find_with_different_certs
@pytest.mark.parametrize('certnick,expected', [("'KRA_AdminV'",
                                                ['ForbiddenException: Authorization Error']),
                                               (random_val,
                                                ['SocketException: Object not found:']),
                                               ("'KRA_AgentR'",
                                                ['FATAL: SSL alert received: CERTIFICATE_REVOKED']),
                                               ("'KRA_AdminE'",
                                                ['FATAL: SSL alert received: CERTIFICATE_EXPIRED']),
                                               ("'KRA_UnPrivilegedV'",
                                                ['ForbiddenException: Authorization Error'])
                                               ])
@pytest.mark.parametrize('protocol', ('https', 'http'))
@pytest.mark.negative
def test_pki_kra_find_with_different_certs(ansible_module, protocol,
                                           certnick, expected):
    """
    :id: 337162c4-6abf-4a9d-bf1e-3a7a9cc48c01

    :Title: RHCS-TC Test pki kra-key-find with different certificates passed.

    :Test: Test pki kra-key-find with different certificates passed.


    :Description:
            This command will test the pki kra-key-find with different certificates having different attributes.

    :Requirement: pki kra-key-find

    :CaseComponent: \-

    :Type:

    :Steps:
           1. pki kra-key-find with KRA_AdminV.
           2. pki kra-key-find with random value.
           3. pki kra-key-find with KRA_AgentR.
           4. pki kra-key-find with KRA_AdminE.
           5. pki kra-key-find with KRA_UnPrivilegedUnTrusted.


    :ExpectedResults:
            1. When KRA_AdminV certnick is passed , it should return result as in Authorization Error.
            2. When random certnick is passed, it should return result as in Object not found.
            3. When KRA_AgentR certnick is passed , it should return result as in CERTIFICATE_REVOKED.
            4. When KRA_AdminE certnick is passed , it should return result as in CERTIFICATE_EXPIRED.
            5. When KRA_UnPrivilegedUnTrusted certnick is passed , it should return result as in
               Authorization Error


    """
    output = ansible_module.pki(cli='kra-key-find',
                                protocol=protocol,
                                certnick=certnick
                                )
    for (result) in output.values():
        assert result['rc'] != 0
        for iter in expected:
            assert iter in result['stderr']


# test_pki_kra_find_with_not_group_member
@pytest.mark.parametrize('certnick,expected', [("'testuser1234'",
                                                ['ForbiddenException: Authorization Error'])])
@pytest.mark.parametrize('protocol', ('https', 'http'))
@pytest.mark.negative
def test_pki_kra_find_with_not_group_member(ansible_module, protocol, certnick, expected):
    """
    :id: 198e3c77-8c1b-4021-9680-d7d2d9d1f75f

    :Title: RHCS-TC Test pki kra-key-find using valid user(Not a member of any group) .

    :Test: Test pki kra-key-find using valid user(Not a member of any group) .


    :Description:
            This command will search keys using valid user(Not a member of any group) .

    :Requirement: pki kra-key-find

    :CaseComponent: \-

    :Type:

    :Steps:
           1. generate a certificate which is not a member of any group.
           1. pki kra-key-find with testuser1234.

    :ExpectedResults:
            1. When testuser1234 certnick is passed , it should return result as in Authorization Error.

    """

    generate_cert.add_user(ansible_module, userid='testuser1234', user_name='testuser1234', subsystem='kra',
                         certnick="'{}'".format(constants.KRA_ADMIN_NICK))
    generate_cert.create_certificate_request(ansible_module)
    generate_cert.process_certificate_request(ansible_module)
    generate_cert.export_certificate(ansible_module)
    generate_cert.add_cert_to_user(ansible_module, userid='testuser1234', subsystem='kra',
                                 port=constants.KRA_HTTP_PORT, certnick="'{}'".format(constants.KRA_ADMIN_NICK))
    generate_cert.add_cert_to_database(ansible_module)

    output = ansible_module.pki(cli='kra-key-find',
                                protocol=protocol,
                                certnick=certnick)
    for (result) in output.values():
        assert result['rc'] != 0
        for iter in expected:
            assert iter in result['stderr']
