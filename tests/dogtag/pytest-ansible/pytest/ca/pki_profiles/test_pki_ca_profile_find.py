"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI CA-PROFILE CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki ca-profile cli commands needs to be tested:
#   pki ca-profile-find
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
import re
import pytest
from pki.testlib.common.utils import UserOperations, ProfileOperations
from pki.testlib.common.certlib import sys, os

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
               'caCMCserverCert', 'caCMCECserverCert',
               'caCMCECsubsystemCert', 'caCMCsubsystemCert',
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
               'caFullCMCSelfSignedCert', 'caECFullCMCSelfSignedCert',
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
               'caSigningUserCert', 'caTokenUserDelegateAuthKeyEnrollment',
               'caTokenUserDelegateSigningKeyEnrollment']


@pytest.mark.parametrize('args', ['--help', 'asdf', ''])
def test_pki_ca_profile_find_help(ansible_module, args):
    """
    :Title: Test pki ca-profile-find  --help command.
    :Description: test pki ca-profile-find --help command
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c
           SECret.123 -n "PKI CA Administrator for Example.Org"
           ca-profile-find --help
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c
        SECret.123 -n "PKI CA Administrator for Example.Org"
        ca-profile-find asdf
    :Expected results:
        1. It should return help message.
    """
    cmd_out = ansible_module.pki(cli="ca-profile-find",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(args))
    for result in cmd_out.values():
        if args == '--help':
            assert result['rc'] == 0
            assert "usage: ca-profile-find [OPTIONS...]" in result['stdout']
            assert "-debug           Run in debug mode." in result['stdout']
            assert "--size <size>     Page size" in result['stdout']
            assert "--start <start>   Page start" in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        elif args == 'asdf':
            assert result['rc'] >= 1
            assert 'ERROR: Too many arguments specified.' in result['stderr']
            log.info("Successfully run : '{}'".format(result['cmd']))
        elif args == '':
            if result['rc'] == 0:
                assert 'Number of entries returned 20' in result['stdout']
                log.info("Successfully ran : '{}'".format(result['cmd']))
                raw_prof_id = re.findall("Profile ID: .*", result['stdout'])
                prof_id = [i.split(":")[1].strip() for i in raw_prof_id]
                for i in prof_id:
                    assert i in CA_PROFILES
            else:
                log.error("Failed to run : {}".format(result['cmd']))
                log.error(result['stdout'])
                log.error(result['stderr'])
                pytest.fail()


@pytest.mark.parametrize('args', ['5', '123456789123354', '-128'])
def test_pki_ca_profile_find_with_profile_size(ansible_module, args):
    """
    :Title: pki ca-profile-find with cert size value
    :Description: Execute pki ca-profile-find with --size 5 and
                  verify 5 profiles are returned
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c
           SECret.123 -n "PKI CA Administrator for Example.Org"
           ca-profile-find --size 5
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c
           SECret.123 -n "PKI CA Administrator for Example.Org"
           ca-profile-find --size 123456789123354
        3. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c
           SECret.123 -n "PKI CA Administrator for Example.Org"
           ca-profile-find --size -128
    :Expected results:
        1. It should return a fixed number of search results

    """
    cmd_out = ansible_module.pki(cli="ca-profile-find",
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
                raw_prof_id = re.findall("Profile ID: .*", result['stdout'])
                prof_id = [i.split(":")[1].strip() for i in raw_prof_id]
                assert len(prof_id) == 5
            else:
                log.error("Failed to run : {}".format(result['cmd']))
                log.error(result['stdout'])
                log.error(result['stderr'])
                pytest.fail()

        elif args == '123456789123354':
            if result['rc'] >= 1:
                assert 'NumberFormatException: For input string: ' \
                       '\"123456789123354\"' in result['stderr']
                log.info("Successfully ran : '{}'".format(result['cmd']))
            else:
                log.error("Failed to run : {}".format(result['cmd']))
                log.error(result['stdout'])
                log.error(result['stderr'])
                pytest.fail()

        elif args == '-128':
            if 'Number of entries returned' in result['stdout']:
                # It should fail for negative value but its passing
                # RH Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1224644
                pytest.skip('https://bugzilla.redhat.com/show_bug.cgi?id=1224644')
            else:
                assert 'NumberFormatException: For input string: \"-128\"' in result['stderr']
                log.info('Successfully ran : {}'.format(result['cmd']))
                log.info('RH Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1224644')


@pytest.mark.parametrize('start, size', [(0, 0), (0, 5), (5, 0), (5, 5)])
def test_pki_ca_profile_find_with_different_profile_size_and_start_value(start, size, ansible_module):
    """
    :Title: pki ca-profile-find with different cert size and start value
    :Description: Issue pki ca-profile-find with --size 5 --start 5
                  and verify 5 results are returned
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "PKI CA Administrator for Example.Org" ca-profile-find --start 0 --size 0
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "PKI CA Administrator for Example.Org" ca-profile-find --start 0 --size 5
        3. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "PKI CA Administrator for Example.Org" ca-profile-find --start 5 --size 0
        4. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "PKI CA Administrator for Example.Org" ca-profile-find --start 5 --size 5
    :Expected results:
        1. It should return a fixed number of search results

    """
    cmd_out = ansible_module.pki(cli="ca-profile-find",
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
            log.error("Failed to run : {}".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


def test_pki_ca_profile_find_with_junk_value_in_start_option(ansible_module):
    """
    :Title: pki ca-profile-find with junk as a profile start value
    :Description: Issue pki ca-profile-find with --start <junkvalue>
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "PKI CA Administrator for Example.Org" ca-profile-find --size fgdhdkjfkdkdk
    :Expected results:
        1. It should return a NumberFormatException

    """
    profile_start = "fgdhdkjfkdkdk"
    cmd_out = ansible_module.pki(cli="ca-profile-find",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='--start {}'.format(profile_start))
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert 'NumberFormatException: For input string: \"fgdhdkjfkdkdk\"' in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


@pytest.mark.parametrize("valid_user_cert", ["CA_AdminV", "CA_AgentV", "CA_AuditV"])
def test_pki_ca_profile_find_with_valid_user_cert(valid_user_cert, ansible_module):
    """
    :Title: pki ca-profile-find with different valid user's cert
    :Description: Executing pki ca-profile-find using valid user cert should pass
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "CA_AdminV" ca-profile-find
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "CA_AgentV" ca-profile-find
        3. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "CA_AuditV" ca-profile-find
    :Expected results:
        1. It should return Certificates

    """
    cmd_out = ansible_module.pki(cli="ca-profile-find",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(valid_user_cert))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Number of entries returned 20' in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


@pytest.mark.parametrize("revoked_user_cert", ["CA_AdminR", "CA_AgentR", "CA_AuditR"])
def test_pki_ca_profile_find_with_revoked_user_cert(revoked_user_cert, ansible_module):
    """
    :Title: pki ca-profile-find with different revoked user's cert
    :Description: Executing pki ca-profile-find using revoked user cert
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
          -n "CA_AdminR" ca-profile-find
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
          -n "CA_AgentR" ca-profile-find
        3. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
          -n "CA_AuditR" ca-profile-find
    :Expected results:
        1. It should throw an Exception.

    """
    cmd_out = ansible_module.pki(cli="ca-profile-find",
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
            log.error("Failed to run : {}".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


@pytest.mark.parametrize("expired_user_cert", ["CA_AdminE", "CA_AgentE", "CA_AuditE"])
def test_pki_ca_profile_find_with_expired_user_cert(expired_user_cert, ansible_module):
    """
    :Title: pki ca-profile-find with different user's expired cert
    :Description: Executing pki ca-profile-find using expired user cert
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "CA_AdminE" ca-profile-find
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "CA_AgentE" ca-profile-find
        3. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "CA_AuditE" ca-profile-find
    :Expected results:
        1. It should return an Unauthorised Exception.

    """
    cmd_out = ansible_module.pki(cli="ca-profile-find",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(expired_user_cert))
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


def test_pki_ca_profile_find_with_invalid_user(ansible_module):
    """
    :Title: pki ca-profile-find with invalid user's cert
    :Description: Issue pki ca-profile-find with invalid user
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -u pki_user -w Secret123 ca-profile-find
    :Expected results:
        1. It should return an Unauthorised Exception.

    """
    command_out = ansible_module.pki(cli="ca-profile-find",
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
            log.error("Failed to run : {}".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


def test_pki_ca_profile_find_with_normal_user_cert(ansible_module):
    """
    :Title: pki ca-profile-find with normal user cert
    :Description: Issue pki ca-profile-find with normal user cert should fail
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Add User
        2. Generate User Cert
        3. Add Cert to User
        4. Add User cert in database
        5. find profile using the same user cert
    :Expected results:
        1. It should return an Forbidden Exception.
    """
    user = 'testUserFooBar'
    fullName = 'testUserFooBar'
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

    cmd_out = ansible_module.pki(cli="ca-profile-find",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(user))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Number of entries returned 20" in result['stdout']
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


def test_add_ca_profile_and_find_when_it_is_enabled(ansible_module):
    """
    :Title: pki ca-profile-add and find when profile is enabled
    :Description: Issue pki ca profile add and find when it is enabled
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Create profile
        2. Add Profile
        3. Enable Profile
        4. Find the enabled profile using ca-profile-find
    :Expected results:
        1. It should return an profile name
    """
    # Create the profile
    profile_xml_output = '/tmp/caUserCertFooBar2.xml'
    profile_name = 'testUserFooBar1'
    stored = profop.get_profile_to_xml(ansible_module, profile_name='caUserCert',
                                       profile_path=profile_xml_output)
    assert stored
    ansible_module.replace(dest=profile_xml_output, regexp='caUserCert', replace='testUserFooBar1')
    ansible_module.fetch(src=profile_xml_output, dest=profile_xml_output, flat=True)

    # Add new created profile
    profop.add_profile(ansible_module, profile_name, profile_xml_output)

    # Enable new added profile
    profop.enable_profile(ansible_module, profile_name)

    # Find enabled profile
    cmd_out = ansible_module.pki(cli="ca-profile-find",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='--size {}'.format('1000'))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Profile ID: {}".format(profile_name) in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            log.info("Failed to ran : '{}'".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Disable new added profile
    profop.disable_profile(ansible_module, profile_name)
    # Delete the profile
    profop.delete_profile(ansible_module, profile_name)
    ansible_module.command('rm -rf {}'.format(profile_xml_output))
    os.remove(profile_xml_output)


def test_add_ca_profile_and_find_when_it_is_disabled(ansible_module):
    """
    :Title: pki ca-profile-add and find when profile is disabled
    :Description: Issue pki ca profile add and find when it is disabled
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Create profile
        2. Add Profile
        3. Disable Profile
        4. Find the disabled profile using ca-profile-find
    :Expected results:
        1. It should return an profile name
    """
    # Create the profile
    profile_xml_output = '/tmp/caUserCertFooBar3.xml'
    profile_name = 'testUserFooBar2'
    stored = profop.get_profile_to_xml(ansible_module, profile_name='caUserCert',
                                       profile_path=profile_xml_output)
    assert stored
    ansible_module.replace(dest=profile_xml_output, regexp='caUserCert', replace='testUserFooBar2')
    ansible_module.fetch(src=profile_xml_output, dest=profile_xml_output, flat=True)

    # Add new created profile
    profop.add_profile(ansible_module, profile_name, profile_xml_output)

    # Disable new added profile
    profop.disable_profile(ansible_module, profile_name)

    # Find disabled profile
    cmd_out = ansible_module.pki(cli="ca-profile-find",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='--size {}'.format('1000'))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Profile ID: {}".format(profile_name) in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            log.info("Failed to ran : '{}'".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Delete the profile
    profop.delete_profile(ansible_module, profile_name)
    ansible_module.command('rm -rf {}'.format(profile_xml_output))
    os.remove(profile_xml_output)


def test_ca_profile_find_and_parse_in_profiles_directory(ansible_module):
    """
    :Title: pki ca-profile-find and check with profile directory
    :Description: Issue pki ca profile and check with profile directory
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. ca-profile-find and parse with config file
    :Expected results:
        1. It should return an profile name which not enabled by default
    """
    # Fetch profiles from /ca/profiles/ca/ directory
    profiles_path = '/var/lib/pki/{}/ca/profiles/ca/'.format(constants.CA_INSTANCE_NAME)
    fetch_profiles = ansible_module.command('ls {}'.format(profiles_path))
    raw_profiles = [i['stdout'] for i in fetch_profiles.values()]
    output = [i.split(".")[0] for i in raw_profiles[0].split("\n")]

    # Find the ca profiles
    cmd_out = ansible_module.pki(cli="ca-profile-find",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format("--size 100"))
    for result in cmd_out.values():
        if result['rc'] == 0:
            raw_prof_id = re.findall("Profile ID: .*", result['stdout'])
            prof_id = [i.split(":")[1].strip() for i in raw_prof_id]
            for i in output:
                try:
                    assert i in prof_id
                except Exception as e:
                    log.info("Not Enabled by default | Profile Not Found : {}".format(i))
        else:
            log.error("Failed to find profiles : {}".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
