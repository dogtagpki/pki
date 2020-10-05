"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI ca-kraconnector-show CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki ca-kraconnector commands needs to be tested:
#           pki ca-kraconnector-show
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
#   warrunty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
#   PURPOSE. See the GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public
#   License along with this program; if not, write to the Free
#   Software Foundation, Inc., 51 Frunklin Street, Fifth Floor,
#   Boston, MA 02110-1301, USA.
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""
import logging

from pki.testlib.common.certlib import *
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
logging.basicConfig(stream=sys.stdout, level=logging.INFO)


@pytest.mark.parametrize('args', ['--help', 'asdf', ''])
def test_pki_ca_kraconnector_show_help(ansible_module, args):
    """
    :Title: Test pki ca-kraconnector-show  --help command.
    :Description: test pki ca-kraconnector-show --help command
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c
                SECret.123 -n "PKI CA Administrator for Example.Org" ca-kraconnector-show --help
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c
                SECret.123 -n "PKI CA Administrator for Example.Org"  ca-kraconnector-show asdf
    :Expected results:
        1. It should return help message.
    """
    cmd_out = ansible_module.pki(cli="ca-kraconnector-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(args))
    for result in cmd_out.values():
        if args == '--help':
            assert result['rc'] == 0
            assert "usage: ca-kraconnector-show [OPTIONS...]" in result['stdout']
            log.info("Successfully run : '{}'".format(result['cmd']))
        else:
            assert 'Enabled: true' in result['stdout']
            assert 'Local: false' in result['stdout']
            assert 'URI: /kra/agent/kra/connector' in result['stdout']
            assert 'Transport Cert' in result['stdout']
            log.info("Successfully run : '{}'".format(result['cmd']))


def test_pki_ca_kraconnector_show_as_anonymous_user(ansible_module):
    """
    :Title: pki ca-kraconnector-show as anonymous user
    :Description: Execute pki ca-kraconnector-show as anonymous user should fail
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -u caAgentFoobaar
            -w secret -h pki1.example.com -c SECret.123 ca-kraconnector-show
    :Expected results:
        2. It should return Unauthorized Exception
    """
    command_out = ansible_module.pki(cli="ca-kraconnector-show",
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     authType='basicAuth',
                                     hostname=constants.MASTER_HOSTNAME,
                                     username='"{}"'.format("pki_user"),
                                     userpassword='"{}"'.format("Secret123"),
                                     extra_args="--host {} --port {}".format(constants.MASTER_HOSTNAME,
                                                                             constants.KRA_HTTP_PORT))
    for result in command_out.values():
        if result['rc'] >= 1:
            assert 'PKIException: Unauthorized' in result['stderr']
            log.info('Successfully run : {}'.format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))


def test_pki_ca_kraconnector_show(ansible_module):
    """
    :Title: test for ca-kraconnaector-show
    :Description: Testing ca-kraconnector-show
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :Setup: Use the subsystems and database setup with all certificates in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
                -n 'admin cert' ca-kraconnector-show --host pki1.example.com --port 20080
    :Expectedresults:
        1. It should show success message
    """
    cmd_out = ansible_module.pki(cli="ca-kraconnector-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick="'{}'".format(constants.CA_ADMIN_NICK))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Host: {}'.format(constants.MASTER_HOSTNAME) in result['stdout']
            assert 'Enabled: true' in result['stdout']
            assert 'Local: false' in result['stdout']
            assert 'URI: /kra/agent/kra/connector' in result['stdout']
            log.info("Successfully run : '{}'".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            log.info("Failed to run : '{}'".format(result['cmd']))
            pytest.xfail()


@pytest.mark.parametrize("valid_user_cert", ["CA_AdminV", "CA_AgentV", "CA_AuditV"])
def test_pki_ca_kraconnector_show_with_valid_user_cert(valid_user_cert, ansible_module):
    """
    :Title: test for ca-kraconnector-show
    :Description: Testing ca-kraconnector-show with valid Admin, Valid Administrator,Agent,Operator & UnPrivileged
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :Setup: Use the subsystems and database setup with all certificates in ansible to run subsystem commands
    :Steps:
        1. Run command : pki -p 20080 -d nssdb -c SECret.123 -n "Valid Certificate" ca-kraconnector-show
    :Expectedresults:
        1. It should show success message
    """
    # Running ca-kraconnector-show cli with valid user
    cmd_out = ansible_module.pki(cli="ca-kraconnector-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick=valid_user_cert)
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert "ForbiddenException: Authorization Error" in result['stderr']
            log.info("Successfully run : '{}'".format(result['cmd']))
        else:
            assert result['rc'] == 0
            log.info("Failed to run '{}'".format(result['cmd']))
            pytest.xfail()


@pytest.mark.parametrize("revoked_user_cert", ["CA_AdminR", "CA_AgentR", "CA_AuditR"])
def test_pki_ca_kraconnector_show_with_revoked_user_cert(revoked_user_cert, ansible_module):
    """
    :Title: test for ca-kraconnector-show
    :Description: Testing ca-kraconnector-show with Expired Admin, Valid Administrator,Agent,Operator & UnPrivileged
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :Setup: Use the subsystems and database setup with all certificates in ansible to run subsystem commands
    :Steps:
        1. Run command : pki -p 20080 -d nssdb -c SECret.123 -n "Revoked user Certificate" ca-kraconnector-show
    :Expectedresults:
        1. Failed with error Expired message ERROR
    """
    # Running ca-kraconnector-show cli with Revoked certficate
    cmd_out = ansible_module.pki(cli="ca-kraconnector-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick=revoked_user_cert)
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert "PKIException: Unauthorized" in result['stderr']
            log.info("Successfully run : '{}'".format(result['cmd']))
        else:
            assert result['rc'] == 0
            log.info("Failed to run '{}'".format(result['cmd']))
            pytest.xfail()


@pytest.mark.parametrize("expired_user_cert", ["CA_AdminE", "CA_AgentE", "CA_AuditE"])
def test_pki_ca_kraconnector_show_with_expired_user_cert(expired_user_cert, ansible_module):
    """
    :Title: pki ca-kraconnector-show with different user's expired cert
    :Description: Executing pki ca-kraconnector-show using expired user cert
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
                -c SECret.123 -n "CA_AdminE" ca-kraconnector-show
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
                -c SECret.123 -n "CA_AgentE" ca-kraconnector-show
        3. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
                -c SECret.123 -n "CA_AuditE" ca-kraconnector-show
    :Expected results:
        1. It should return an Certificate Unknown Exception.
    """
    # Running ca-kraconnector-show cli with Expired certficate
    cmd_out = ansible_module.pki(cli="ca-kraconnector-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick=expired_user_cert)
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert "CERTIFICATE_EXPIRED" in result['stderr']
            log.info("Successfully run : '{}'".format(result['cmd']))
        else:
            assert result['rc'] == 0
            log.info("Failed to run '{}'".format(result['cmd']))
            pytest.xfail()


def test_pki_ca_kraconnector_show_with_invalid_user(ansible_module):
    """
    :Title: pki ca-kraconnector-show with invalid user's cert
    :Description: Issue pki ca-kraconnector-show with invalid user
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -u pki_user -w Secret123 ca-kraconnector-show caAgentFoobar
    :Expected results:
        1. It should return an Unauthorised Exception.
    """
    # Running ca-kraconnector-show cli with invalid user certficate
    command_out = ansible_module.pki(cli="ca-kraconnector-show",
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
            log.info('Successfully run : {}'.format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            pytest.xfail()


def test_pki_ca_kraconnector_show_with_normal_user_cert(ansible_module):
    """
    :Title: pki ca-kraconnector-show with normal user cert
    :Description: Issue pki ca-kraconnector-show with normal user cert should fail
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Add User
        2. Generate User Cert
        3. Add Cert to User
        4. Add User cert in database
        5. Show kraconnector using the same user cert
    :Expected results:
        1. It should return an Forbidden Exception.
    """
    # Adding the user
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
    # Assigning the cert to user
    ansible_module.pki(cli='ca-user-cert-add',
                       nssdb=constants.NSSDB,
                       dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                       port=constants.CA_HTTP_PORT,
                       hostname=constants.MASTER_HOSTNAME,
                       certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                       extra_args='{} --serial {}'.format(user, cert_id))
    # Adding user cert in database
    cert_import = 'pki -d {} -c {} -p {} -h {} client-cert-import "{}" ' \
                  '--serial {}'.format(constants.NSSDB,
                                       constants.CLIENT_DIR_PASSWORD,
                                       constants.CA_HTTPS_PORT,
                                       constants.MASTER_HOSTNAME, user,
                                       cert_id)
    ansible_module.command(cert_import)
    # Running ca-kraconnector-show cli with normal user cert
    cmd_out = ansible_module.pki(cli="ca-kraconnector-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(user))
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert "ForbiddenException: Authorization Error" in result['stderr']
            log.info("Successfully run : '{}'".format(result['cmd']))
        else:
            log.info("Failed to run : '{}'".format(result['cmd']))
            pytest.fail()
    # Remove Added user
    userop.remove_user(ansible_module, user)
    # Remove the cert from nssdb
    cert_remove = 'pki -d {} -c {} -p {} -h {} client-cert-del {}'.format(
        constants.NSSDB,
        constants.CLIENT_DIR_PASSWORD,
        constants.CA_HTTPS_PORT,
        constants.MASTER_HOSTNAME, user)
    ansible_module.command(cert_remove)


def test_pki_ca_kraconnector_show_with_invalid_cert(ansible_module):
    """
    :Title: pki ca-kraconnector-show with invalid cert
    :Description: Issue pki ca-kraconnector-show with invalid cert
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Show kraconnector with invalid cert pki -d certdb -p 20080
                -c SECret.123 -n "Invalid cert" ca-kraconnector-show
    :Expected results:
        1. It should return an Forbidden Exception.
    """
    # Running ca-kraconnector-show cli with invalid certficate
    cmd_out = ansible_module.pki(cli="ca-kraconnector-show",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick="FooBaar")
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert "Certificate not found: FooBaar" in result['stderr']
            log.info("Successfully run : '{}'".format(result['cmd']))
        else:
            assert result['rc'] == 0
            log.info("Successfully run : '{}'".format(result['cmd']))
            pytest.fail()
