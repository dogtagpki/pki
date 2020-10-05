"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: ca-feature tests for show
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Deepak Punia
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
from pki.testlib.common.certlib import os,sys,pytest
from pki.testlib.common.utils import ProfileOperations, UserOperations
import binascii

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

userop = UserOperations(nssdb=constants.NSSDB)
profop = ProfileOperations(nssdb=constants.NSSDB)

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout)


@pytest.mark.parametrize('args', ['--help',binascii.b2a_hex(os.urandom(10)), ''])
def test_pki_ca_feature_show_help(ansible_module, args):
    """
    :Title: Test pki ca-feature-show  --help command.
    :Description: test pki ca-feature-show --help command
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c
           SECret.123 -n "PKI CA Administrator for Example.Org"
           ca-feature-show --help
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c
        SECret.123 -n "PKI CA Administrator for Example.Org"
        ca-feature-show asdf
    :Expected results:
        1. It should return help message.
    """
    cmd_out = ansible_module.pki(cli="ca-feature-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(args))
    for result in cmd_out.values():
        if args == '--help':
            assert result['rc'] == 0
            assert "usage: ca-feature-show <ID>" in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        elif args == '':
            assert result['rc'] >= 1
            assert 'ERROR: No ID specified.' in result['stderr']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            assert 'ResourceNotFoundException' in result['stderr']
            log.info("Successfully run : '{}'".format(result['cmd']))



@pytest.mark.parametrize('args', ('authorityu', '--', 'authority'))
def test_pki_feature_show_authority(ansible_module, args):
    """
    :Title: Test pki ca-feature-show with '' and authorityu message.
    :Description: Test pki ca-feature-show with '' and authorityu message.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-feature-show with ''
        2. Run pki ca-feature-show with authorityu
        3. Run pki ca-feature-show with authority
    :Expectedresults:
        1. It should show error message.
        2. It should show error message.
        3. it should show authority detail
    """
    #Show error message
    cmd_out = ansible_module.pki(cli="ca-feature-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(args))
    for result in cmd_out.values():
        if args == 'authorityu':
            assert result['rc'] >= 1
            assert "ResourceNotFoundException" in result['stderr']
        if args == '--':
            assert result['rc'] >= 1
            assert "ERROR: No ID specified." in result['stderr']
        if args == 'authority':
            assert result['rc'] == 0
            assert "ID:             authority" in result['stdout']
            assert "Description:    Lightweight CAs" in result['stdout']
            assert "Enabled:        true" in result['stdout']
            log.info("Successfully run : {}".format(result['stdout']))


def test_pki_ca_feature_show_as_non_existing_authority(ansible_module):
    """
    :Title: pki ca-feature-show as non-existing authority
    :Description: Issue pki ca-feature-show as non-existing authority should fail
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "PKI CA Administrator for Example.Org" ca-feature-show NonExistingAuthority
    :Expected results:
        1. It should return a NotFound Exception

    """
    cmd_out = ansible_module.pki(cli="ca-feature-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format('NonExistingAuthority'))
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert 'ResourceNotFoundException' in result['stderr']
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            pytest.fail()


def test_pki_ca_feature_show_as_anonymous_authority(ansible_module):
    """
    :Title: pki ca-feature-show as anonymous authority
    :Description: Execute pki ca-feature-show as anonymous authority should fail
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
           -c SECret.123 ca-feature-show caAgentFoobar
    :Expected results:
        2. It should return Forbidden Exception

    """
    command = 'pki -d {} -c {} -h {} -p {} ca-feature-show {}'.format(
        constants.NSSDB,
        constants.CLIENT_DIR_PASSWORD,
        constants.MASTER_HOSTNAME,
        constants.CA_HTTPS_PORT, 'caAgentFoobar')
    cmd_out = ansible_module.command(command)
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert 'ResourceNotFoundException' in result['stderr']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            pytest.fail()

@pytest.mark.parametrize("valid_user_cert", ["CA_AdminV", "CA_AgentV", "CA_AuditV"])
def test_pki_ca_feature_show_with_valid_user_cert(valid_user_cert, ansible_module):
    """
    :Title: pki ca-feature-show with different valid user's cert
    :Description: Executing pki ca-feature-show using valid user cert should pass
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
           -c SECret.123 -n "CA_AdminV" ca-feature-show authority
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
           -c SECret.123 -n "CA_AgentV" ca-feature-show authority
        3. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
           -c SECret.123 -n "CA_AuditV" ca-feature-show authority
    :Expected results:
        1. It should return authority detail with valid certificate

    """
    cmd_out = ansible_module.pki(cli="ca-feature-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(valid_user_cert),
                                 extra_args='{}'.format('authority'))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'ID:             authority' in result['stdout']
            assert 'Description:    Lightweight CAs' in result['stdout']
            assert 'Enabled:        true' in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            pytest.fail()


@pytest.mark.parametrize("revoked_user_cert", ["CA_AdminR", "CA_AgentR", "CA_AuditR"])
def test_pki_ca_feature_show_with_revoked_user_cert(revoked_user_cert, ansible_module):
    """
    :Title: pki ca-feature-show with different revoked user's cert
    :Description: Executing pki ca-feature-show using revoked user cert
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
           -c SECret.123 -n "CA_AdminR" ca-feature-show authority
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
           -c SECret.123 -n "CA_AgentR" ca-feature-show authority
        3. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
           -c SECret.123 -n "CA_AuditR" ca-feature-show authority
    :Expected results:
        1. It should throw an Exception.

    """
    cmd_out = ansible_module.pki(cli="ca-feature-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(revoked_user_cert),
                                 extra_args='{}'.format('authority'))
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert 'PKIException: Unauthorized' in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            pytest.fail()


@pytest.mark.parametrize("expired_user_cert", ["CA_AdminE", "CA_AgentE", "CA_AuditE"])
def test_pki_ca_feature_show_with_expired_user_cert(expired_user_cert, ansible_module):
    """
    :Title: pki ca-feature-show with different user's expired cert
    :Description: Executing pki ca-feature-show using expired user cert
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
           -c SECret.123 -n "CA_AdminE" ca-feature-show authority
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
           -c SECret.123 -n "CA_AgentE" ca-feature-show authority
        3. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
           -c SECret.123 -n "CA_AuditE" ca-feature-show authority
    :Expected results:
        1. It should return an Certificate Unknown Exception.

    """
    cmd_out = ansible_module.pki(cli="ca-feature-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(expired_user_cert),
                                 extra_args='{}'.format('authority'))
    for result in cmd_out.values():
        if result['rc'] >= 0:
            assert "CERTIFICATE_EXPIRED" in result['stderr']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] == 1
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.fail()


def test_pki_ca_feature_show_with_invalid_user(ansible_module):
    """
    :Title: pki ca-feature-show with invalid user's cert
    :Description: Issue pki ca-feature-show with invalid user
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -u pki_user -w Secret123 ca-feature-show authority
    :Expected results:
        1. It should return an Unauthorised Exception.

    """
    command_out = ansible_module.pki(cli="ca-feature-show",
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     authType='basicAuth',
                                     hostname=constants.MASTER_HOSTNAME,
                                     username='"{}"'.format("pki_user"),
                                     userpassword='"{}"'.format("Secret123"),
                                     extra_args='{}'.format('authority'))
    for result in command_out.values():
        if result['rc'] >= 1:
            assert 'PKIException: Unauthorized' in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            pytest.fail()


def test_pki_ca_feature_show_with_normal_user_cert(ansible_module):
    """
    :Title: pki ca-feature-show with normal user cert
    :Description: Issue pki ca-feature-show with normal user cert should success
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Add User
        2. Generate User Cert
        3. Add Cert to User
        4. Add User cert in database
        5. Show authority using the same user cert
    :Expected results:
        1. It should return an success message.
    """
    #Add User
    user = 'testUserCert'
    fullName = 'testUserCert'
    subject = "UID={},CN={}".format(user, fullName)
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    cert_id = userop.process_certificate_request(ansible_module,
                                                 subject=subject,
                                                 request_type='pkcs10',
                                                 algo='rsa',
                                                 keysize='2048',
                                                 authority='caUserCert')
    #Add Cert to User
    ansible_module.pki(cli='ca-user-cert-add',
                       nssdb=constants.NSSDB,
                       dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                       port=constants.CA_HTTP_PORT,
                       hostname=constants.MASTER_HOSTNAME,
                       certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                       extra_args='{} --serial {}'.format(user, cert_id))
    #Add User cert in database
    cert_import = 'pki -d {} -c {} -p {} -h {} client-cert-import "{}" ' \
                  '--serial {}'.format(constants.NSSDB,
                                       constants.CLIENT_DIR_PASSWORD,
                                       constants.CA_HTTPS_PORT,
                                       constants.MASTER_HOSTNAME, user,
                                       cert_id)
    ansible_module.command(cert_import)
    #how authority using the same user cert
    cmd_out = ansible_module.pki(cli="ca-feature-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(user),
                                 extra_args='{}'.format('authority'))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'ID:             authority' in result['stdout']
            assert 'Description:    Lightweight CAs' in result['stdout']
            assert 'Enabled:        true' in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.fail()

    # Remove the cert from nssdb
    cert_remove = 'pki -d {} -c {} -p {} -h {} client-cert-del {}'.format(
        constants.NSSDB,
        constants.CLIENT_DIR_PASSWORD,
        constants.CA_HTTPS_PORT,
        constants.MASTER_HOSTNAME, user)
    ansible_module.command(cert_remove)
