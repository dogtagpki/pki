"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: ca-authority tests for show
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
import re,binascii
from pki.testlib.common.utils import ProfileOperations, UserOperations

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


@pytest.mark.parametrize('args', ['--help', binascii.b2a_hex(os.urandom(10)), ''])
def test_pki_ca_authority_show_help(ansible_module, args):
    """
    :Title: Test pki ca-authority-show  --help command.
    :Description: test pki ca-authority-show --help command
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c
                SECret.123 -n "PKI CA Administrator for Example.Org" ca-authority-show --help
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c
                SECret.123 -n "PKI CA Administrator for Example.Org" ca-authority-show asdf
    :Expected results:
        1. It should return help message.
    """
    cmd_out = ansible_module.pki(cli="ca-authority-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(args))
    for result in cmd_out.values():
        if args == '--help':
            assert result['rc'] == 0
            assert "--host-authority   Show host authority" in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        elif args == '':
            assert result['rc'] >= 1
            assert 'ERROR: No ID specified.' in result['stderr']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            assert 'BadRequestException' in result['stderr']
            log.info("Successfully run : '{}'".format(result['cmd']))


@pytest.mark.parametrize('args', ('--host-authorityu', '--', '--host-authority'))
def test_pki_authority_show_authority(ansible_module, args):
    """
    :Title: Test pki ca-authority-show with '--', --host-authorityu and --host-authority message.
    :Description: Test pki ca-authority-show with '' and --host-authorityu message.
    :Requirement: Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-authority-show with '--'
        2. Run pki ca-authority-show with a --host-authorityu
        3. Run pki ca-authority-show with a --host-authority
    :Expectedresults:
        1. It should show error message.
        2. It should show error message.
        3. it should show success message.
    """
    cmd_out = ansible_module.pki(cli="ca-authority-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(args))
    for result in cmd_out.values():
        if args == '--host-authorityu':
            assert result['rc'] >= 1
            assert "Unrecognized option: --host-authorityu" in result['stderr']
        if args == '--':
            assert result['rc'] >= 1
            assert "ERROR: No ID specified." in result['stderr']
        if args == '--host-authority':
            assert result['rc'] == 0
            assert "Host authority: true" in result['stdout']
            assert "Serial no:      1" in result['stdout']
            assert "Enabled:        true" in result['stdout']
            assert "Ready to sign:  true" in result['stdout']
            assert "Description:    Host authority" in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))


def test_pki_ca_authority_show_as_non_existing_authority(ansible_module):
    """
    :Title: pki ca-authority-show as non-existing authority
    :Description: Issue pki ca-authority-show as non-existing authority should fail
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "PKI CA Administrator for Example.Org" ca-authority-show NonExistingProfile
    :Expected results:
        1. It should return a NotFound Exception
    """
    cmd_out = ansible_module.pki(cli="ca-authority-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format('NonExistingAuthority'))
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert 'BadRequestException' in result['stderr']
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            pytest.fail()


def test_pki_ca_authority_show_as_anonymous_id(ansible_module):
    """
    :Title: pki ca-authority-show as anonymous user
    :Description: Execute pki ca-authority-show as anonymous user should fail
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
           -c SECret.123 ca-authority-show caAgentFoobar
    :Expected results:
        2. It should return Forbidden Exception

    """
    command = 'pki -d {} -c {} -n {} -h {} -p {} ca-authority-show {}'.format(
        constants.NSSDB,
        constants.CLIENT_DIR_PASSWORD, "caAgentFoobar",
        constants.MASTER_HOSTNAME,
        constants.CA_HTTPS_PORT, '--host-authority')
    cmd_out = ansible_module.command(command)
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert 'Certificate not found: caAgentFoobar' in result['stderr']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            pytest.fail()


@pytest.mark.parametrize("valid_user_cert", ["CA_AdminV", "CA_AgentV", "CA_AuditV"])
def test_pki_ca_authority_show_with_valid_user_cert(valid_user_cert, ansible_module):
    """
    :Title: pki ca-authority-show with different valid user's cert
    :Description: Executing pki ca-authority-show using valid user cert should pass
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
                -c SECret.123 -n "CA_AdminV" ca-authority-show authority
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
                -c SECret.123 -n "CA_AgentV" ca-authority-show authority
        3. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
                -c SECret.123 -n "CA_AuditV" ca-authority-show authority
    :Expected results:
        1. It should return Certificates
    """
    # find the host authority id
    authority_id_find = ansible_module.pki(cli="ca-authority-find",
                                           nssdb=constants.NSSDB,
                                           dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                           port=constants.CA_HTTP_PORT,
                                           hostname=constants.MASTER_HOSTNAME,
                                           certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                           extra_args='--dn "CN=CA Signing Certificate,'
                                                      'OU={},O={}"'.format(constants.CA_INSTANCE_NAME,
                                                                           constants.CA_SECURITY_DOMAIN_NAME))
    for result in authority_id_find.values():
        authority_id = re.findall('ID:.*', result['stdout'])
        authority_id = authority_id[0].split(":")[1].strip()
    # show the host authority with valid certficate
    cmd_out = ansible_module.pki(cli="ca-authority-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick=valid_user_cert,
                                 extra_args="{}".format(authority_id))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Host authority: true" in result['stdout']
            assert "Authority DN:" in result['stdout']
            assert "ID:             {}".format(authority_id) in result['stdout']
            assert "Issuer DN:" in result['stdout']
            assert "Serial no:      1" in result['stdout']
            assert "Enabled:        true" in result['stdout']
            assert "Ready to sign:  true" in result['stdout']
            assert "Description:    Host authority" in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.fail()


@pytest.mark.parametrize("revoked_user_cert", ["CA_AdminR", "CA_AgentR", "CA_AuditR"])
def test_pki_ca_authority_show_with_revoked_user_cert(revoked_user_cert, ansible_module):
    """
    :Title: pki ca-authority-show with different revoked user's cert
    :Description: Executing pki ca-authority-show using revoked user cert
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
                -c SECret.123 -n "CA_AdminR" ca-authority-show authority
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
                -c SECret.123 -n "CA_AgentR" ca-authority-show authority
        3. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
                -c SECret.123 -n "CA_AuditR" ca-authority-show authority
    :Expected results:
        1. It should throw an Exception.

    """
    # find the host authority id
    authority_id_find = ansible_module.pki(cli="ca-authority-find",
                                           nssdb=constants.NSSDB,
                                           dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                           port=constants.CA_HTTP_PORT,
                                           hostname=constants.MASTER_HOSTNAME,
                                           certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                           extra_args='--dn "CN=CA Signing Certificate,'
                                                      'OU={},O={}"'.format(constants.CA_INSTANCE_NAME,
                                                                           constants.CA_SECURITY_DOMAIN_NAME))
    for result in authority_id_find.values():
        authority_id = re.findall('ID:.*', result['stdout'])
        authority_id = authority_id[0].split(":")[1].strip()
    # show the host authority with revoked certficate
    cmd_out = ansible_module.pki(cli="ca-authority-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick=revoked_user_cert,
                                 extra_args="{}".format(authority_id))
    for result in cmd_out.values():
        if result['rc'] >= 0:
            assert "PKIException: Unauthorized" in result['stderr']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] == 1
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.fail()


@pytest.mark.parametrize("expired_user_cert", ["CA_AdminE", "CA_AgentE", "CA_AuditE"])
def test_pki_ca_authority_show_with_expired_user_cert(expired_user_cert, ansible_module):
    """
    :Title: pki ca-authority-show with different user's expired cert
    :Description: Executing pki ca-authority-show using expired user cert
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
                -c SECret.123 -n "CA_AdminE" ca-authority-show authority
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
                -c SECret.123 -n "CA_AgentE" ca-authority-show authority
        3. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
                -c SECret.123 -n "CA_AuditE" ca-authority-show authority
    :Expected results:
        1. It should return an Certificate Unknown Exception.

    """
    # find the host authority id
    authority_id_find = ansible_module.pki(cli="ca-authority-find",
                                           nssdb=constants.NSSDB,
                                           dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                           port=constants.CA_HTTP_PORT,
                                           hostname=constants.MASTER_HOSTNAME,
                                           certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                           extra_args='--dn "CN=CA Signing Certificate,'
                                                      'OU={},O={}"'.format(constants.CA_INSTANCE_NAME,
                                                                           constants.CA_SECURITY_DOMAIN_NAME))
    for result in authority_id_find.values():
        authority_id = re.findall('ID:.*', result['stdout'])
        authority_id = authority_id[0].split(":")[1].strip()
    # show the host authority with revoked certficate
    cmd_out = ansible_module.pki(cli="ca-authority-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick=expired_user_cert,
                                 extra_args="{}".format(authority_id))
    for result in cmd_out.values():
        if result['rc'] >= 0:
            assert "CERTIFICATE_EXPIRED" in result['stderr']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] == 1
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.fail()


def test_pki_ca_authority_show_with_invalid_user(ansible_module):
    """
    :Title: pki ca-authority-show with invalid user's cert
    :Description: Issue pki ca-authority-show with invalid user
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
               -u pki_user -w Secret123 ca-authority-show authority
    :Expected results:
        1. It should return an Unauthorised Exception.
    """
    # find the host authority id
    authority_id_find = ansible_module.pki(cli="ca-authority-find",
                                           nssdb=constants.NSSDB,
                                           dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                           port=constants.CA_HTTP_PORT,
                                           hostname=constants.MASTER_HOSTNAME,
                                           certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                           extra_args='--dn "CN=CA Signing Certificate,'
                                                      'OU={},O={}"'.format(constants.CA_INSTANCE_NAME,
                                                                           constants.CA_SECURITY_DOMAIN_NAME))
    for result in authority_id_find.values():
        authority_id = re.findall('ID:.*', result['stdout'])
        authority_id = authority_id[0].split(":")[1].strip()
    # Test the show authority with invalid user
    command_out = ansible_module.pki(cli="ca-authority-show",
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     authType='basicAuth',
                                     hostname=constants.MASTER_HOSTNAME,
                                     username='"{}"'.format("pki_user"),
                                     userpassword='"{}"'.format("Secret123"),
                                     extra_args='{}'.format(authority_id))
    for result in command_out.values():
        if result['rc'] >= 1:
            assert 'PKIException: Unauthorized' in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            pytest.fail()


def test_pki_ca_authority_show_with_normal_user_cert(ansible_module):
    """
    :Title: pki ca-authority-show with normal user cert
    :Description: Issue pki ca-authority-show with normal user cert should success
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
    # Create the user
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
    # Add the cert to user
    ansible_module.pki(cli='ca-user-cert-add',
                       nssdb=constants.NSSDB,
                       dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                       port=constants.CA_HTTP_PORT,
                       hostname=constants.MASTER_HOSTNAME,
                       certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                       extra_args='{} --serial {}'.format(user, cert_id))
    # Import the user cert to db
    cert_import = 'pki -d {} -c {} -p {} -h {} client-cert-import "{}" ' \
                  '--serial {}'.format(constants.NSSDB,
                                       constants.CLIENT_DIR_PASSWORD,
                                       constants.CA_HTTPS_PORT,
                                       constants.MASTER_HOSTNAME, user,
                                       cert_id)
    ansible_module.command(cert_import)
    # find the authirity id
    authority_id_find = ansible_module.pki(cli="ca-authority-find",
                                           nssdb=constants.NSSDB,
                                           dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                           port=constants.CA_HTTP_PORT,
                                           hostname=constants.MASTER_HOSTNAME,
                                           certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                           extra_args='--dn "CN=CA Signing Certificate,'
                                                      'OU={},O={}"'.format(constants.CA_INSTANCE_NAME,
                                                                           constants.CA_SECURITY_DOMAIN_NAME))
    for result in authority_id_find.values():
        authority_id = re.findall('ID:.*', result['stdout'])
        authority_id = authority_id[0].split(":")[1].strip()
    # Show authority with authority id
    cmd_out = ansible_module.pki(cli="ca-authority-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(user),
                                 extra_args='{}'.format(authority_id))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Host authority: true" in result['stdout']
            assert "Authority DN:" in result['stdout']
            assert "ID:             {}".format(authority_id) in result['stdout']
            assert "Issuer DN:" in result['stdout']
            assert "Serial no:      1" in result['stdout']
            assert "Enabled:        true" in result['stdout']
            assert "Ready to sign:  true" in result['stdout']
            assert "Description:    Host authority" in result['stdout']
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
