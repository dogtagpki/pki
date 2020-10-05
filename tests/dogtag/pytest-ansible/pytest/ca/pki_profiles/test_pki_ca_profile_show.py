"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI CA-PROFILE CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki ca-profile cli commands needs to be tested:
#   pki ca-profile-show
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
from pki.testlib.common.utils import ProfileOperations, UserOperations
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

CA_PROFILES = ['acmeServerCert', 'caServerKeygen_UserCert', 'caServerKeygen_DirUserCert',
               'caCMCserverCert', 'caCMCECserverCert', 'caCMCECsubsystemCert',
               'caCMCsubsystemCert',
               'caCMCauditSigningCert', 'caCMCcaCert', 'caCMCocspCert',
               'caCMCkraTransportCert',
               'caCMCkraStorageCert', 'caUserCert', 'caECUserCert',
               'caUserSMIMEcapCert', 'caDualCert',
               'caDirBasedDualCert', 'AdminCert', 'ECAdminCert',
               'caSignedLogCert', 'caTPSCert', 'caRARouterCert',
               'caRouterCert', 'caServerCert', 'caECServerCert',
               'caSubsystemCert', 'caECSubsystemCert', 'caOtherCert',
               'caCACert', 'caCrossSignedCACert', 'caInstallCACert',
               'caRACert', 'caOCSPCert', 'caStorageCert',
               'caTransportCert', 'caDirPinUserCert', 'caECDirPinUserCert',
               'caDirUserCert', 'caECDirUserCert',
               'caAgentServerCert', 'caECAgentServerCert',
               'caAgentFileSigning', 'caCMCUserCert', 'caCMCECUserCert',
               'caFullCMCUserCert', 'caECFullCMCUserCert',
               'caFullCMCUserSignedCert', 'caECFullCMCUserSignedCert',
               'caFullCMCSharedTokenCert', 'caECFullCMCSharedTokenCert',
               'caSimpleCMCUserCert', 'caECSimpleCMCUserCert',
               'caTokenDeviceKeyEnrollment',
               'caTokenUserEncryptionKeyEnrollment',
               'caTokenUserSigningKeyEnrollment',
               'caTempTokenDeviceKeyEnrollment',
               'caTempTokenUserEncryptionKeyEnrollment',
               'caTempTokenUserSigningKeyEnrollment', 'caAdminCert',
               'caECAdminCert', 'caInternalAuthServerCert',
               'caECInternalAuthServerCert', 'caInternalAuthTransportCert',
               'caInternalAuthDRMstorageCert',
               'caInternalAuthSubsystemCert', 'caECInternalAuthSubsystemCert',
               'caInternalAuthOCSPCert',
               'caInternalAuthAuditSigningCert', 'DomainController',
               'caDualRAuserCert', 'caRAagentCert',
               'caRAserverCert', 'caUUIDdeviceCert', 'caSSLClientSelfRenewal',
               'caDirUserRenewal', 'caManualRenewal',
               'caTokenMSLoginEnrollment', 'caTokenUserSigningKeyRenewal',
               'caTokenUserEncryptionKeyRenewal',
               'caTokenUserAuthKeyRenewal', 'caJarSigningCert',
               'caIPAserviceCert', 'caEncUserCert',
               'caSigningUserCert']


@pytest.mark.parametrize('args', ['--help', 'asdf', ''])
def test_pki_ca_profile_show_help(ansible_module, args):
    """
    :Title: Test pki ca-profile-show  --help command.
    :Description: test pki ca-profile-show --help command
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c
           SECret.123 -n "PKI CA Administrator for Example.Org"
           ca-profile-show --help
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c
        SECret.123 -n "PKI CA Administrator for Example.Org"
        ca-profile-show asdf
    :Expected results:
        1. It should return help message.
    """
    cmd_out = ansible_module.pki(cli="ca-profile-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(args))
    for result in cmd_out.values():
        if args == '--help':
            assert result['rc'] == 0
            assert "usage: ca-profile-show <Profile ID> [OPTIONS...]" in result['stdout']
            assert "--debug               Run in debug mode." in result['stdout']
            assert "--output <filename>   Output filename" in result['stdout']
            assert "--raw                 Use raw format" in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        elif args == 'asdf':
            assert result['rc'] >= 1
            assert 'ProfileNotFoundException: Profile ID asdf not found' in result['stderr']
            log.info("Successfully run : '{}'".format(result['cmd']))
        elif args == '':
            assert result['rc'] >= 1
            assert 'ERROR: No Profile ID specified.' in result['stderr']
            log.info("Successfully ran : '{}'".format(result['cmd']))


def test_pki_ca_profile_show_all_profiles(ansible_module):
    """
    :Title: pki ca-profile-show all profiles
    :Description: Execute pki ca-profile-show information of all the profiles
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c
           SECret.123 -n "PKI CA Administrator for Example.Org" ca-profile-show
    :Expected results:
        1. It should return All Certs.

    """
    for i in CA_PROFILES:
        cmd_out = ansible_module.pki(cli="ca-profile-show",
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='{}'.format(i))
        for result in cmd_out.values():
            if result['rc'] == 0:
                assert 'Profile ID: {}'.format(i) in result['stdout']
            else:
                assert result['rc'] >= 1
                log.error("Failed to run : {}".format(result['cmd']))
                log.error(result['stdout'])
                log.error(result['stderr'])
                pytest.fail()


def test_pki_ca_profile_show_as_non_existing_profile(ansible_module):
    """
    :Title: pki ca-profile-show as non-existing profile
    :Description: Issue pki ca-profile-show as non-existing profile should fail
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "PKI CA Administrator for Example.Org" ca-profile-show NonExistingProfile
    :Expected results:
        1. It should return a NotFound Exception

    """
    cmd_out = ansible_module.pki(cli="ca-profile-show",
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


def test_pki_ca_profile_show_as_anonymous_user(ansible_module):
    """
    :Title: pki ca-profile-show as anonymous user
    :Description: Execute pki ca-profile-show as anonymous user should fail
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
           -c SECret.123 ca-profile-show caAgentFoobar
    :Expected results:
        2. It should return Forbidden Exception

    """
    command = 'pki -d {} -c {} -h {} -P http -p {} ca-profile-show {}'.format(
        constants.NSSDB,
        constants.CLIENT_DIR_PASSWORD,
        constants.MASTER_HOSTNAME,
        constants.CA_HTTP_PORT, 'caAgentFoobar')
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


def test_pki_ca_profile_show_disabled_profile(ansible_module):
    """
    :Title: pki ca-profile-show to view disabled profile
    :Description: Issue pki cert-profile-show to view disabled profile
                  and verify results are returned
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
           -c SECret.123 -n "PKI CA Administrator for Example.Org"
           ca-profile-disable caAgentFoobar
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
           -c SECret.123 -n "PKI CA Administrator for Example.Org"
           ca-profile-show caAgentFoobar
    :Expected results:
        1. It should return a profile details

    """
    # Disable the profile
    profop.disable_profile(ansible_module, 'caAgentFoobar')

    cmd_out = ansible_module.pki(cli="ca-profile-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format('caAgentFoobar'))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Profile ID: caAgentFoobar' in result['stdout']
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    profop.enable_profile(ansible_module, 'caAgentFoobar')


def test_pki_ca_profile_show_with_output_option(ansible_module):
    """
    :Title: pki ca-profile-show with output option
    :Description: Issue pki ca-profile-show with output option and
                  verify output is generated
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "PKI CA Administrator for Example.Org" ca-profile-show --output test.xml
    :Expected results:
        1. It should create a profile with specific name

    """
    profile_path = '/tmp/testprofile.xml'
    cmd_out = ansible_module.pki(cli="ca-profile-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --output {}'.format(
                                     'caAgentFoobar', profile_path))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Saved profile caAgentFoobar to {}'.format(profile_path) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
            is_file = ansible_module.stat(path=profile_path)
            for r1 in is_file.values():
                assert r1['stat']['exists']
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    ansible_module.command('rm -rf {}'.format(profile_path))


def test_pki_ca_profile_show_output_with_disabled_profile(ansible_module):
    """
    :Title: pki ca-profile-show with output option on disabled profile
    :Description: Issue pki ca-profile-show with output option on disabled profile &
                  verify output is generated
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "PKI CA Administrator for Example.Org" ca-profile-disable caAgentFoobar
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "PKI CA Administrator for Example.Org"
           ca-profile-show caAgentFoobar --output test.xml
    :Expected results:
        1. It should create a profile with specific name

    """
    profile_path = '/tmp/testprofile.xml'

    # Disable the profile
    profop.disable_profile(ansible_module, 'caAgentFoobar')

    cmd_out = ansible_module.pki(cli="ca-profile-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --output {}'.format(
                                     'caAgentFoobar', profile_path))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Saved profile caAgentFoobar to {}'.format(profile_path) in result['stdout']
            assert 'Profile "caAgentFoobar"' in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    ansible_module.command('rm -rf {}'.format(profile_path))
    profop.enable_profile(ansible_module, 'caAgentFoobar')


@pytest.mark.parametrize("valid_user_cert", ["CA_AdminV", "CA_AgentV", "CA_AuditV"])
def test_pki_ca_profile_show_with_valid_user_cert(valid_user_cert, ansible_module):
    """
    :Title: pki ca-profile-show with different valid user's cert
    :Description: Executing pki ca-profile-show using valid user cert should pass
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
           -c SECret.123 -n "CA_AdminV" ca-profile-show caAgentFoobar
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
           -c SECret.123 -n "CA_AgentV" ca-profile-show caAgentFoobar
        3. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
           -c SECret.123 -n "CA_AuditV" ca-profile-show caAgentFoobar
    :Expected results:
        1. It should return Certificates

    """
    cmd_out = ansible_module.pki(cli="ca-profile-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(valid_user_cert),
                                 extra_args='{}'.format('caAgentFoobar'))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Profile "caAgentFoobar"' in result['stdout']
            assert 'Profile ID: caAgentFoobar' in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


@pytest.mark.parametrize("revoked_user_cert", ["CA_AdminR", "CA_AgentR", "CA_AuditR"])
def test_pki_ca_profile_show_with_revoked_user_cert(revoked_user_cert, ansible_module):
    """
    :Title: pki ca-profile-show with different revoked user's cert
    :Description: Executing pki ca-profile-show using revoked user cert
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
           -c SECret.123 -n "CA_AdminR" ca-profile-show caAgentFoobar
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
           -c SECret.123 -n "CA_AgentR" ca-profile-show caAgentFoobar
        3. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
           -c SECret.123 -n "CA_AuditR" ca-profile-show caAgentFoobar
    :Expected results:
        1. It should throw an Exception.

    """
    cmd_out = ansible_module.pki(cli="ca-profile-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(revoked_user_cert),
                                 extra_args='{}'.format('caAgentFoobar'))
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert 'PKIException: Unauthorized' in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


@pytest.mark.parametrize("expired_user_cert", ["CA_AdminE", "CA_AgentE", "CA_AuditE"])
def test_pki_ca_profile_show_with_expired_user_cert(expired_user_cert, ansible_module):
    """
    :Title: pki ca-profile-show with different user's expired cert
    :Description: Executing pki ca-profile-show using expired user cert
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
           -c SECret.123 -n "CA_AdminE" ca-profile-show caAgentFoobar
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
           -c SECret.123 -n "CA_AgentE" ca-profile-show caAgentFoobar
        3. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
           -c SECret.123 -n "CA_AuditE" ca-profile-show caAgentFoobar
    :Expected results:
        1. It should return an Certificate Unknown Exception.

    """
    cmd_out = ansible_module.pki(cli="ca-profile-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(expired_user_cert),
                                 extra_args='{}'.format('caAgentFoobar'))
    for result in cmd_out.values():
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


def test_pki_ca_profile_show_with_invalid_user(ansible_module):
    """
    :Title: pki ca-profile-show with invalid user's cert
    :Description: Issue pki ca-profile-show with invalid user
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -u pki_user -w Secret123 ca-profile-show caAgentFoobar
    :Expected results:
        1. It should return an Unauthorised Exception.

    """
    command_out = ansible_module.pki(cli="ca-profile-show",
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     authType='basicAuth',
                                     hostname=constants.MASTER_HOSTNAME,
                                     username='"{}"'.format("pki_user"),
                                     userpassword='"{}"'.format("Secret123"),
                                     extra_args='{}'.format('caAgentFoobar'))
    for result in command_out.values():
        if result['rc'] >= 1:
            assert 'PKIException: Unauthorized' in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


def test_pki_ca_profile_show_with_normal_user_cert(ansible_module):
    """
    :Title: pki ca-profile-show with normal user cert
    :Description: Issue pki ca-profile-show with normal user cert should fail
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Add User
        2. Generate User Cert
        3. Add Cert to User
        4. Add User cert in database
        5. Show profile using the same user cert
    :Expected results:
        1. It should return an Forbidden Exception.
    """
    user = 'testUserCert'
    fullName = 'testUserCert'
    subject = "UID={},CN={}".format(user, fullName)
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
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

    cmd_out = ansible_module.pki(cli="ca-profile-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(user),
                                 extra_args='{}'.format('caAgentFoobar'))
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert "ForbiddenException: Authorization Error" in result['stderr']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.xfail()

    # Remove the cert from nssdb
    userop.remove_client_cert(ansible_module, user, subsystem='ca')

    # Remove the user
    userop.remove_user(ansible_module, user, subsystem='ca')
