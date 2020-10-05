"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI CA-PROFILE CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki ca-profile cli commands needs to be tested:
#   pki ca-profile-disable
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Pritam Singh <prisingh@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2018 Red Hat, Inc. All rights reserved.
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
from pki.testlib.common.exceptions import PkiLibException
from pki.testlib.common.utils import UserOperations, ProfileOperations
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


@pytest.mark.parametrize('args', ['--help', 'asdf'])
def test_pki_ca_profile_disable_help(ansible_module, args):
    """
    :Title: Test pki ca-profile-disable  --help command.
    :Description: test pki ca-profile-disable help command
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "PKI CA Administrator for Example.Org" ca-profile-disable --help
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "PKI CA Administrator for Example.Org" ca-profile-disable asdf
    :Expected results:
        1. It should return help message.
    """
    cmd_out = ansible_module.pki(cli="ca-profile-disable",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(args))
    for result in cmd_out.values():
        if args == '--help':
            assert result['rc'] == 0
            assert "usage: ca-profile-disable <Profile ID> [OPTIONS...]" in result['stdout']
            assert "--debug     Run in debug mode." in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        elif args == 'asdf':
            assert result['rc'] >= 1
            assert 'ProfileNotFoundException: Profile ID asdf not found' in result['stderr']
            log.info("Successfully run : '{}'".format(result['cmd']))


def test_pki_ca_profile_disable_when_profile_is_enabled(ansible_module):
    """
    :Title: pki ca-profile-disable when profile is enabled
    :Description: Execute pki ca-profile-disable when profile is enabled
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "PKI CA Administrator for Example.Org" ca-profile-disable caAgentFoobar
    :Expected results:
        1. It should disable the profile

    """
    # Create the profile
    profile_xml_output = '/tmp/caUserCertFooBar1.xml'
    profile_name = 'testcaUserCert1'
    stored = profop.get_profile_to_xml(ansible_module, profile_name='caUserCert',
                                       profile_path=profile_xml_output)
    assert stored
    ansible_module.replace(dest=profile_xml_output, regexp='caUserCert', replace='testcaUserCert1')

    # Add new created profile
    profop.add_profile(ansible_module, profile_name, profile_xml_output)

    # Enable new added profile
    profop.enable_profile(ansible_module, profile_name)

    # Disable the profile
    cmd_out = ansible_module.pki(cli="ca-profile-disable",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(profile_name))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Disabled profile "{}"'.format(profile_name) in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    profop.delete_profile(ansible_module, profile_name)
    ansible_module.command('rm -rf {}'.format(profile_xml_output))


def test_pki_ca_profile_disable_to_check_enable_the_profile_and_disable_it(ansible_module):
    """
    :Title: pki ca-profile-disable to check enabling the profile and disable it
    :Description: Execute pki ca-profile-disable to check enabling the profile & disable it
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "PKI CA Administrator for Example.Org" ca-profile-enable caAgentFoobar
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "PKI CA Administrator for Example.Org" ca-profile-disable caAgentFoobar
    :Expected results:
        1. It should enable the profile and check for re-disabling the profile

    """
    # Create the profile
    profile_xml_output = '/tmp/caUserCertFooBar2.xml'
    profile_name = 'testcaUserCert2'
    stored = profop.get_profile_to_xml(ansible_module, profile_name='caUserCert',
                                       profile_path=profile_xml_output)
    assert stored
    ansible_module.replace(dest=profile_xml_output, regexp='caUserCert', replace='testcaUserCert2')

    # Add new created profile
    profop.add_profile(ansible_module, profile_name, profile_xml_output)

    # Enable the profile
    cmd_out = ansible_module.pki(cli="ca-profile-enable",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(profile_name))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Enabled profile "{}"'.format(profile_name) in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Disable the profile
    cmd_out = ansible_module.pki(cli="ca-profile-disable",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(profile_name))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Disabled profile "{}"'.format(profile_name) in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    profop.delete_profile(ansible_module, profile_name)
    ansible_module.command('rm -rf {}'.format(profile_xml_output))


def test_pki_ca_profile_disable_as_anonymous_user(ansible_module):
    """
    :Title: pki ca-profile-disable as anonymous user
    :Description: Execute pki ca-profile-disable as anonymous user should fail
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
           -c SECret.123 ca-profile-disable caAgentFoobar
    :Expected results:
        2. It should return Forbidden Exception

    """
    # Create the profile
    profile_xml_output = '/tmp/caUserCertFooBar3.xml'
    profile_name = 'testcaUserCert3'
    stored = profop.get_profile_to_xml(ansible_module, profile_name='caUserCert',
                                       profile_path=profile_xml_output)
    assert stored
    ansible_module.replace(dest=profile_xml_output, regexp='caUserCert', replace='testcaUserCert3')

    # Add new created profile
    profop.add_profile(ansible_module, profile_name, profile_xml_output)

    # Enable new added profile
    profop.enable_profile(ansible_module, profile_name)

    # Disable the profile using anonymous user
    command = 'pki -d {} -c {} -h {} -P http -p {} ca-profile-disable {}'.format(
        constants.NSSDB,
        constants.CLIENT_DIR_PASSWORD,
        constants.MASTER_HOSTNAME,
        constants.CA_HTTP_PORT, profile_name)
    cmd_out = ansible_module.command(command)
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert 'ForbiddenException: No user principal provided.' in result['stderr']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    profop.disable_profile(ansible_module, profile_name)
    profop.delete_profile(ansible_module, profile_name)
    ansible_module.command('rm -rf {}'.format(profile_xml_output))


def test_pki_ca_disable_as_non_existing_profile(ansible_module):
    """
    :Title: pki ca-profile-disable as non-existing profile
    :Description: Issue pki ca-profile-disable as non-existing profile should fail
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "PKI CA Administrator for Example.Org" ca-profile-disable NonExistingProfile
    :Expected results:
        1. It should return a NotFound Exception

    """
    cmd_out = ansible_module.pki(cli="ca-profile-disable",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format('NonExistingProfile'))
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert 'ProfileNotFoundException: Profile ID NonExistingProfile not found' in result['stderr']
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


def test_pki_ca_profile_disable_already_disabled_profile(ansible_module):
    """
    :Title: pki ca-profile-disable to check disabling already disable profile
    :Description: Issue pki ca-profile-disable to check disabling already disabled
                  profile should fail
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "PKI CA Administrator for Example.Org" ca-profile-disable caAgentFoobar
    :Expected results:
        1. It should return a Conflict Exception

    """
    # Create the profile
    profile_xml_output = '/tmp/caUserCertFooBar4.xml'
    profile_name = 'testcaUserCert4'
    stored = profop.get_profile_to_xml(ansible_module, profile_name='caUserCert',
                                       profile_path=profile_xml_output)
    assert stored
    ansible_module.replace(dest=profile_xml_output, regexp='caUserCert', replace='testcaUserCert4')

    # Add new created profile
    profop.add_profile(ansible_module, profile_name, profile_xml_output)

    # Disable new added profile
    profop.disable_profile(ansible_module, profile_name)

    # Disable the already disabled profile
    cmd_out = ansible_module.pki(cli="ca-profile-disable",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(profile_name))
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert 'ConflictingOperationException: Profile already disabled' in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    profop.delete_profile(ansible_module, profile_name)
    ansible_module.command('rm -rf {}'.format(profile_xml_output))


@pytest.mark.parametrize("valid_user_cert", ["CA_AdminV", "CA_AgentV", "CA_AuditV"])
def test_pki_ca_profile_disable_with_valid_user_cert(valid_user_cert, ansible_module):
    """
    :Title: pki ca-profile-disable with different valid user's cert
    :Description: Executing pki ca-profile-disable using valid user cert should pass
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "CA_AdminV" ca-profile-disable caAgentFoobar
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "CA_AgentV" ca-profile-disable caAgentFoobar
        3. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "CA_AuditV" ca-profile-disable caAgentFoobar
    :Expected results:
        1. It should return Forbidden Exception
        2. It should disable the profile
        3. It should return a Forbidden Exception.

    """
    # Create the profile
    profile_xml_output = '/tmp/caUserCertFooBar5.xml'
    profile_name = 'testcaUserCert5'
    stored = profop.get_profile_to_xml(ansible_module, profile_name='caUserCert',
                                       profile_path=profile_xml_output)
    assert stored
    ansible_module.replace(dest=profile_xml_output, regexp='caUserCert', replace='testcaUserCert5')

    # Add new created profile
    profop.add_profile(ansible_module, profile_name, profile_xml_output)

    # Enable new added profile
    profop.enable_profile(ansible_module, profile_name)

    # Disable the profile with different valid user cert
    cmd_out = ansible_module.pki(cli="ca-profile-disable",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(valid_user_cert),
                                 extra_args='{}'.format(profile_name))
    for result in cmd_out.values():
        if valid_user_cert in ['CA_AdminV', 'CA_AuditV']:
            if result['rc'] >= 1:
                assert 'ForbiddenException: Authorization Error' in result['stderr']
                log.info('Successfully ran : {}'.format(result['cmd']))
            else:
                log.error("Failed to run : {}".format(result['cmd']))
                log.error(result['stdout'])
                log.error(result['stderr'])
                pytest.fail()
        elif valid_user_cert == 'CA_AgentV':
            if result['rc'] == 0:
                assert 'Disabled profile "{}"'.format(profile_name) in result['stdout']
                log.info('Successfully ran : {}'.format(result['cmd']))
            else:
                log.error("Failed to run : {}".format(result['cmd']))
                log.error(result['stdout'])
                log.error(result['stderr'])
                pytest.fail()

    profop.disable_profile(ansible_module, profile_name)
    profop.delete_profile(ansible_module, profile_name)
    ansible_module.command('rm -rf {}'.format(profile_xml_output))


@pytest.mark.parametrize("revoked_user_cert", ["CA_AdminR", "CA_AgentR", "CA_AuditR"])
def test_pki_ca_profile_disable_with_revoked_user_cert(revoked_user_cert, ansible_module):
    """
    :Title: pki ca-profile-disable with different revoked user's cert
    :Description: Executing pki ca-profile-disable using revoked user cert
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "CA_AdminR" ca-profile-disable caAgentFoobar
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "CA_AgentR" ca-profile-disable caAgentFoobar
        3. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "CA_AuditR" ca-profile-disable caAgentFoobar
    :Expected results:
        1. It should throw an Exception.

    """
    # Create the profile
    profile_xml_output = '/tmp/caUserCertFooBar6.xml'
    profile_name = 'testcaUserCert6'
    stored = profop.get_profile_to_xml(ansible_module, profile_name='caUserCert',
                                       profile_path=profile_xml_output)
    assert stored
    ansible_module.replace(dest=profile_xml_output, regexp='caUserCert', replace='testcaUserCert6')

    # Add new created profile
    profop.add_profile(ansible_module, profile_name, profile_xml_output)

    # Enable new added profile
    profop.enable_profile(ansible_module, profile_name)

    # Disable the profile with different
    cmd_out = ansible_module.pki(cli="ca-profile-disable",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(revoked_user_cert),
                                 extra_args='{}'.format(profile_name))
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert 'PKIException: Unauthorized' in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    profop.disable_profile(ansible_module, profile_name)
    profop.delete_profile(ansible_module, profile_name)
    ansible_module.command('rm -rf {}'.format(profile_xml_output))


@pytest.mark.parametrize("expired_user_cert", ["CA_AdminE", "CA_AgentE", "CA_AuditE"])
def test_pki_ca_profile_disable_with_expired_user_cert(expired_user_cert, ansible_module):
    """
    :Title: pki ca-profile-disable with different user's expired cert
    :Description: Executing pki ca-profile-disable using expired user cert
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "CA_AdminE" ca-profile-disable caAgentFoobar
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "CA_AgentE" ca-profile-disable caAgentFoobar
        3. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "CA_AuditE" ca-profile-disable caAgentFoobar
    :Expected results:
        1. It should return an Unauthorised Exception.

    """
    # Create the profile
    profile_xml_output = '/tmp/caUserCertFooBar7.xml'
    profile_name = 'testcaUserCert7'
    stored = profop.get_profile_to_xml(ansible_module, profile_name='caUserCert',
                                       profile_path=profile_xml_output)
    assert stored
    ansible_module.replace(dest=profile_xml_output, regexp='caUserCert', replace='testcaUserCert7')

    # Add new created profile
    profop.add_profile(ansible_module, profile_name, profile_xml_output)

    # Enable new added profile
    profop.enable_profile(ansible_module, profile_name)

    # Disable the profile with different expired cert
    cmd_out = ansible_module.pki(cli="ca-profile-disable",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(expired_user_cert),
                                 extra_args='{}'.format(profile_name))
    for result in cmd_out.values():
        if result['rc'] == 0:
            log.error("Failed to run : {}".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
        if result['rc'] >= 1:
            assert "SEVERE: FATAL: SSL alert received: CERTIFICATE_EXPIRED\nIOException: " \
                   "SocketException cannot read on socket: Error reading from socket: " \
                   "(-12269) SSL peer rejected your certificate as expired." in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
        profop.disable_profile(ansible_module, profile_name)
        profop.delete_profile(ansible_module, profile_name)

    ansible_module.command('rm -rf {}'.format(profile_xml_output))


def test_pki_ca_profile_disable_with_invalid_user(ansible_module):
    """
    :Title: pki ca-profile-disable with invalid user's cert
    :Description: Issue pki ca-profile-disable with invalid user
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -u pki_user -w Secret123 ca-profile-disable caAgentFoobar
    :Expected results:
        1. It should return an Unauthorised Exception.

    """
    # Create the profile
    profile_xml_output = '/tmp/caUserCertFooBar8.xml'
    profile_name = 'testcaUserCert8'
    stored = profop.get_profile_to_xml(ansible_module, profile_name='caUserCert',
                                       profile_path=profile_xml_output)
    assert stored
    ansible_module.replace(dest=profile_xml_output, regexp='caUserCert', replace='testcaUserCert8')

    # Add new created profile
    profop.add_profile(ansible_module, profile_name, profile_xml_output)

    # Enable new added profile
    profop.enable_profile(ansible_module, profile_name)

    # Disable the profile with invalid user
    command_out = ansible_module.pki(cli="ca-profile-disable",
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     authType='basicAuth',
                                     hostname=constants.MASTER_HOSTNAME,
                                     username='"{}"'.format("pki_user"),
                                     userpassword='"{}"'.format("Secret123"),
                                     extra_args='{}'.format(profile_name))
    for result in command_out.values():
        if result['rc'] >= 1:
            assert 'PKIException: Unauthorized' in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    profop.disable_profile(ansible_module, profile_name)
    profop.delete_profile(ansible_module, profile_name)
    ansible_module.command('rm -rf {}'.format(profile_xml_output))


def test_pki_ca_profile_disable_with_normal_user_cert(ansible_module):
    """
    :Title: pki ca-profile-disable with normal user cert
    :Description: Issue pki ca-profile-disable with normal user cert should fail
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Add User
        2. Generate User Cert
        3. Add Cert to User
        4. Add User cert in database
        5. disable profile using the same user cert
    :Expected results:
        1. It should return an Forbidden Exception.
    """
    user = 'testuserFoobar'
    fullName = 'testuserFoobar'
    subject = "UID={},CN={}".format(user, fullName)
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    cert_id1 = userop.process_certificate_request(ansible_module,
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
                       extra_args='{} --serial {}'.format(user, cert_id1))

    cert_import = 'pki -d {} -c {} -P http -p {} -h {} client-cert-import "{}" ' \
                  '--serial {}'.format(constants.NSSDB,
                                       constants.CLIENT_DIR_PASSWORD,
                                       constants.CA_HTTP_PORT,
                                       constants.MASTER_HOSTNAME, user,
                                       cert_id1)
    ansible_module.command(cert_import)

    # Create the profile
    profile_xml_output = '/tmp/caUserCertFooBar9.xml'
    profile_name = 'testcaUserCert9'
    stored = profop.get_profile_to_xml(ansible_module, profile_name='caUserCert',
                                       profile_path=profile_xml_output)
    assert stored
    ansible_module.replace(dest=profile_xml_output, regexp='caUserCert', replace='testcaUserCert9')

    # Add new created profile
    profop.add_profile(ansible_module, profile_name, profile_xml_output)

    # Enable new added profile
    profop.enable_profile(ansible_module, profile_name)

    # Disable the profile with normal user
    cmd_out = ansible_module.pki(cli="ca-profile-disable",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(user),
                                 extra_args='{}'.format(profile_name))
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert "ForbiddenException: Authorization Error" in result['stderr']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            log.error("Failed to ran : '{}'".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Remove the cert from nssdb
    userop.remove_client_cert(ansible_module, user, subsystem='ca')

    # Remove the user
    userop.remove_user(ansible_module, user, subsystem='ca')

    profop.disable_profile(ansible_module, profile_name)
    profop.delete_profile(ansible_module, profile_name)
    ansible_module.command('rm -rf {}'.format(profile_xml_output))


def test_pki_ca_profile_disable_issue_cert_against_disable_prof(ansible_module):
    """
    :Title: pki test cert request against disabled profile
    :Description: Issue cert request against disabled profile
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Create a profile
        2. Add the profile
        3. Disable the profile
        4. Create cert request against disabled profile
    :Expected results:
        1. It should return an bad request exception

    """
    # Create the profile
    profile_xml_output = '/tmp/caUserCertFooBar10.xml'
    profile_name = 'testcaUserCert10'
    stored = profop.get_profile_to_xml(ansible_module, profile_name='caUserCert',
                                       profile_path=profile_xml_output)
    assert stored
    ansible_module.replace(dest=profile_xml_output, regexp='caUserCert', replace='testcaUserCert10')

    # Add new created profile
    profop.add_profile(ansible_module, profile_name, profile_xml_output)

    # Enable new added profile
    profop.enable_profile(ansible_module, profile_name)

    # Disable the profile
    cmd_out = ansible_module.pki(cli="ca-profile-disable",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(profile_name))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Disabled profile "{}"'.format(profile_name) in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Create Cert request
    user = 'testcaUserCert10'
    fullName = 'testcaUserCert10'
    subject = "UID={},CN={}".format(user, fullName)
    try:
        cert_serial = userop.process_certificate_request(ansible_module, subject=subject, profile=profile_name)
        if cert_serial is None:
            assert True
            log.info("Unable to enroll cert for disabled profile")
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
    except PkiLibException as err:
        log.info("Unable to enroll cert : '{}'".format(err.msg))

    profop.disable_profile(ansible_module, profile_name)
    profop.delete_profile(ansible_module, profile_name)
    ansible_module.command('rm -rf {}'.format(profile_xml_output))
