"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI CA-GROUP CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki ca-group cli commands needs to be tested:
#   pki ca-group-find
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
from pki.testlib.common.utils import UserOperations, ProfileOperations
import pytest
import re

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

CA_GROUPS = ['Certificate Manager Agents', 'Registration Manager Agents', 'Subsystem Group',
             'Trusted Managers', 'Administrators', 'Auditors', 'ClonedSubsystems',
             'Security Domain Administrators', 'Enterprise CA Administrators', 'Enterprise KRA Administrators',
             'Enterprise OCSP Administrators', 'Enterprise TKS Administrators',
             'Enterprise RA Administrators', 'Enterprise TPS Administrators']


@pytest.mark.parametrize('args', ['--help', 'asdf', ''])
def test_pki_ca_group_find_help(ansible_module, args):
    """
    :Title: Test pki ca-group-find  --help command.
    :Description: test pki ca-group-find --help command
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c
           SECret.123 -n "PKI CA Administrator for Example.Org"
           ca-group-find --help
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c
        SECret.123 -n "PKI CA Administrator for Example.Org"
        ca-group-find asdf
        3. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c
        SECret.123 -n "PKI CA Administrator for Example.Org"
        ca-group-find

    :Expected results:
        1. It should return help message.
        2. It should return not match found
        3. It should return no of groups
    """
    cmd_out = ansible_module.pki(cli="ca-group-find",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(args))
    for result in cmd_out.values():
        if args == '--help':
            assert result['rc'] == 0
            assert "usage: ca-group-find [FILTER] [OPTIONS...]" in result['stdout']
            assert "--help" in result['stdout']
            assert "--size <size>     Page size" in result['stdout']
            assert "--start <start>   Page start" in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        elif args == 'asdf':
            assert result['rc'] == 0
            assert '0 entries matched' in result['stdout']
            log.info("Successfully run : '{}'".format(result['cmd']))
        elif args == '':
            if result['rc'] == 0:
                assert 'Number of entries returned 14' in result['stdout']
                log.info("Successfully ran : '{}'".format(result['cmd']))
                raw_group_id = re.findall("Group ID: .*", result['stdout'])
                group_id = [i.split(":")[1].strip() for i in raw_group_id]
                for i in group_id:
                    assert i in CA_GROUPS
            else:
                log.error(result['stdout'])
                log.error(result['stderr'])
                pytest.fail()


@pytest.mark.parametrize('args', ['5', '123456789123354', '-128'])
def test_pki_ca_group_find_with_group_size(ansible_module, args):
    """
    :Title: pki ca-group-find with group size value
    :Description: Execute pki ca-group-find with different group size
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c
           SECret.123 -n "PKI CA Administrator for Example.Org"
           ca-group-find --size 5
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c
           SECret.123 -n "PKI CA Administrator for Example.Org"
           ca-group-find --size 123456789123354
        3. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c
           SECret.123 -n "PKI CA Administrator for Example.Org"
           ca-group-find --size -128
    :Expected results:
        1. It should return a fixed number of search results

    """
    cmd_out = ansible_module.pki(cli="ca-group-find",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='--size {}'.format(args))
    for result in cmd_out.values():
        if args == "5":
            if result['rc'] == 0:
                assert 'Number of entries returned 5' in result['stdout']
                log.info("Successfully ran : '{}'".format(result['cmd']))
                raw_group_id = re.findall("Group ID: .*", result['stdout'])
                group_id = [i.split(":")[1].strip() for i in raw_group_id]
                assert len(group_id) == 5
            else:
                log.error(result['stdout'])
                log.error(result['stderr'])
                pytest.fail()

        elif args == '123456789123354':
            if result['rc'] >= 1:
                assert 'NumberFormatException: For input string: ' \
                       '\"123456789123354\"' in result['stderr']
                log.info("Successfully ran : '{}'".format(result['cmd']))
            else:
                log.error(result['stdout'])
                log.error(result['stderr'])
                pytest.fail()

        elif args == '-128':
            if result['rc'] == 0:
                assert 'Number of entries returned' in result['stdout']
                # It should fail for negative value but its passing
                # RH Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1229906
                log.error("Failed to run : {}".format(result['cmd']))
                pytest.skip('It should fail for negative value but its passing, BZ: 1229906')
            else:
                assert 'NumberFormatException: For input string: \"-128\"' in result['stderr']
                log.info('Successfully ran : {}'.format(result['cmd']))


@pytest.mark.parametrize('start, size', [(0, 0), (0, 5), (5, 0), (5, 5)])
def test_pki_ca_group_find_with_different_group_size_and_start_value(start, size, ansible_module):
    """
    :Title: pki ca-group-find with different group size and start value
    :Description: Issue pki ca-group-find with --size 5 --start 5
                  and verify 5 results are returned
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "PKI CA Administrator for Example.Org" ca-group-find --start 0 --size 0
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "PKI CA Administrator for Example.Org" ca-group-find --start 0 --size 5
        3. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "PKI CA Administrator for Example.Org" ca-group-find --start 5 --size 0
        4. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "PKI CA Administrator for Example.Org" ca-group-find --start 5 --size 5
    :Expected results:
        1. It should return a fixed number of search results

    """
    cmd_out = ansible_module.pki(cli="ca-group-find",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='--start {} --size {}'.format(start, size))
    for result in cmd_out.values():
        if result['rc'] == 0:
            if start == 0 and size == 0:
                assert 'Number of entries returned {}'.format(size) in result['stdout']
                log.info('Successfully ran : {}'.format(result['cmd']))
            elif start == 0 and size == 5:
                assert 'Number of entries returned {}'.format(size) in result['stdout']
                log.info('Successfully ran : {}'.format(result['cmd']))
            elif start == 5 and size == 0:
                assert 'Number of entries returned {}'.format(size) in result['stdout']
                log.info('Successfully ran : {}'.format(result['cmd']))
            elif start == 5 and size == 5:
                assert 'Number of entries returned {}'.format(size) in result['stdout']
                log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


def test_pki_ca_group_find_with_junk_value_in_start_option(ansible_module):
    """
    :Title: pki ca-group-find with junk as a group start value
    :Description: Issue pki ca-group-find with --start <junkvalue>
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "PKI CA Administrator for Example.Org" ca-group-find --size fgdhdkjfkdkdk
    :Expected results:
        1. It should return a NumberFormatException

    """
    group_start = "fgdhdkjfkdkdk"
    cmd_out = ansible_module.pki(cli="ca-group-find",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='--start {}'.format(group_start))
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert 'NumberFormatException: For input string: \"fgdhdkjfkdkdk\"' in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


@pytest.mark.parametrize("valid_user_cert", ["CA_AdminV", "CA_AgentV", "CA_AuditV"])
def test_pki_ca_group_find_with_valid_user_cert(valid_user_cert, ansible_module):
    """
    :Title: pki ca-group-find with different valid user's cert
    :Description: Executing pki ca-group-find using valid user cert should pass
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "CA_AdminV" ca-group-find
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "CA_AgentV" ca-group-find
        3. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "CA_AuditV" ca-group-find
    :Expected results:
        1. It should return Certificates

    """
    cmd_out = ansible_module.pki(cli="ca-group-find",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(valid_user_cert))
    for result in cmd_out.values():
        if valid_user_cert == 'CA_AdminV':
            assert 'Number of entries returned 14' in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        elif valid_user_cert in ['CA_AgentV', 'CA_AuditV']:
            assert result['rc'] >= 1
            assert 'ForbiddenException: Authorization Error' in result['stderr']
            log.info("Successfully ran : {}".format(result['cmd']))


@pytest.mark.parametrize("revoked_user_cert", ["CA_AdminR", "CA_AgentR", "CA_AuditR"])
def test_pki_ca_group_find_with_revoked_user_cert(revoked_user_cert, ansible_module):
    """
    :Title: pki ca-group-find with different revoked user's cert
    :Description: Executing pki ca-group-find using revoked user cert
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
          -n "CA_AdminR" ca-group-find
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
          -n "CA_AgentR" ca-group-find
        3. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
          -n "CA_AuditR" ca-group-find
    :Expected results:
        1. It should throw an Exception.

    """
    cmd_out = ansible_module.pki(cli="ca-group-find",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(revoked_user_cert))
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert 'PKIException: Unauthorized' in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


@pytest.mark.parametrize("expired_user_cert", ["CA_AdminE", "CA_AgentE", "CA_AuditE"])
def test_pki_ca_group_find_with_expired_user_cert(expired_user_cert, ansible_module):
    """
    :Title: pki ca-group-find with different user's expired cert
    :Description: Executing pki ca-group-find using expired user cert
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "CA_AdminE" ca-group-find
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "CA_AgentE" ca-group-find
        3. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "CA_AuditE" ca-group-find
    :Expected results:
        1. It should return an Unauthorised Exception.

    """
    cmd_out = ansible_module.pki(cli="ca-group-find",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(expired_user_cert))
    for result in cmd_out.values():
        if result['rc'] == 0:
            log.error("Failed to run : {}".format(result['cmd']))
            pytest.xfail()
        if result['rc'] >= 1:
            assert "SEVERE: FATAL: SSL alert received: CERTIFICATE_EXPIRED\nIOException: " \
                   "SocketException cannot read on socket: Error reading from socket: " \
                   "(-12269) SSL peer rejected your certificate as expired." in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


def test_pki_ca_group_find_with_invalid_user(ansible_module):
    """
    :Title: pki ca-group-find with invalid user's cert
    :Description: Issue pki ca-group-find with invalid user
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -u pki_user -w Secret123 ca-group-find
    :Expected results:
        1. It should return an Unauthorised Exception.

    """
    command_out = ansible_module.pki(cli="ca-group-find",
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     authType='basicAuth',
                                     hostname=constants.MASTER_HOSTNAME,
                                     username='"{}"'.format("pki_user"),
                                     userpassword='"{}"'.format("Secret123"))
    for result in command_out.values():
        if result['rc'] >= 1:
            assert 'PKIException: Unauthorized' in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


def test_pki_ca_group_find_with_normal_user_cert(ansible_module):
    """
    :Title: pki ca-group-find with normal user cert
    :Description: Issue pki ca-group-find with normal user cert should fail
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Add User
        2. Generate User Cert
        3. Add Cert to User
        4. Add User cert in database
        5. Find group using the same user cert
    :Expected results:
        1. It should return an Forbidden Exception.
    """
    user = 'testUserFooBar'
    fullName = 'testUserFooBar'
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

    cmd_out = ansible_module.pki(cli="ca-group-find",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(user))
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


@pytest.mark.parametrize("valid_filters", ['Administrator', 'KRA', 'TP'])
def test_pki_ca_group_find_with_different_filters(ansible_module, valid_filters):
    """
    :Title: pki ca-group-find with different filter's
    :Description: Issue pki ca-group-find with different filter's
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "PKI CA Administrator for Example.Org" ca-group-find Administrator
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "PKI CA Administrator for Example.Org" ca-group-find KRA
        3. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "PKI CA Administrator for Example.Org" ca-group-find TP
    :Expected results:
        1. It should sort the search result via filtered pattern

    """
    cmd_out = ansible_module.pki(cli="ca-group-find",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(valid_filters))
    for result in cmd_out.values():
        if valid_filters == 'Administrator':
            assert 'Number of entries returned 8' in result['stdout']
            assert valid_filters in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        elif valid_filters == "KRA":
            assert 'Number of entries returned 1' in result['stdout']
            assert valid_filters in result['stdout']
            log.info("Successfully ran : {}".format(result['cmd']))
        elif valid_filters == 'TP':
            assert result['rc'] >= 1
            assert 'BadRequestException: Filter is too short.' in result['stderr']
            log.info("Successfully ran : {}".format(result['cmd']))
