"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   Description: PKI ca-kraconnector-add CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki ca-kraconnector commands needs to be tested:
#   pki ca-kraconnector-add
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
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


@pytest.mark.parametrize('args', ['--help', 'asdf', ' '])
def test_pki_ca_kraconnector_add_help(ansible_module, args):
    """
    :Title: Test pki ca-kraconnector-add  --help command.
    :Description: test pki ca-kraconnector-add --help command
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c
                SECret.123 -n "PKI CA Administrator for Example.Org" ca-kraconnector-add --help
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c
                SECret.123 -n "PKI CA Administrator for Example.Org"  ca-kraconnector-add asdf
    :Expected results:
        1. It should return help message.
    """
    cmd_out = ansible_module.pki(cli="ca-kraconnector-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(args))
    for result in cmd_out.values():
        if args == '--help':
            assert result['rc'] == 0
            assert "usage: ca-kraconnector-add --input-file <file>" in result['stdout']
            log.info("Successfully run : '{}'".format(result['cmd']))
        elif args == 'asdf':
            assert result['rc'] >= 1
            assert 'ERROR: Too many arguments specified' in result['stderr']
            log.info("Successfully run : '{}'".format(result['cmd']))
        elif args == ' ':
            assert 'BadRequestException' in result['stderr']
            log.info("Successfully run : '{}'".format(result['cmd']))


def test_pki_ca_kraconnector_add_as_anonymous_user(ansible_module):
    """
    :Title: pki ca-kraconnector-add as anonymous user
    :Description: Execute pki ca-kraconnector-add as anonymous user should fail
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -u caAgentFoobar
           -c SECret.123 ca-kraconnector-add --host pki1.example.com --port 21080
    :Expected results:
        2. It should return Forbidden Exception
    """
    # add ca kraconnector with anonymous user
    command_out = ansible_module.pki(cli="ca-kraconnector-add",
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


def test_pki_ca_kraconnector_add(ansible_module):
    """
    :Title: test for ca-kraconnaector-add
    :Description: Testing ca-kraconnector-add
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :Setup: Use the subsystems and database setup with all certificates in ansible to run subsystem commands
    :Steps:
        1. Run command : pki -p 23080 -d nssdb -c SECret.123
                -n "Admin Cert" ca-kraconnector-add --host pki1.example.com --port 21080
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
                -n 'admin cert' ca-kraconnector-show --host pki1.example.com --port 21080
    :Expectedresults:
        1. It should show success message
    """
    cmd_out = ansible_module.pki(cli="ca-kraconnector-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                 extra_args="--host {} --port {}".format(constants.MASTER_HOSTNAME,
                                                                         constants.KRA_HTTP_PORT))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added KRA host "{}:{}"'.format(constants.MASTER_HOSTNAME,
                                                   constants.KRA_HTTP_PORT) in result['stdout']
            log.info("Successfully run : '{}'".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            log.info("Failed to run : '{}'".format(result['cmd']))
            pytest.xfail()

    cmd_out = ansible_module.pki(cli="ca-kraconnector-del",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                 extra_args="--host {} --port {}".format(constants.MASTER_HOSTNAME,
                                                                         constants.KRA_HTTP_PORT))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Removed KRA host "{}:{}"'.format(constants.MASTER_HOSTNAME,
                                                     constants.KRA_HTTP_PORT) in result['stdout']
            log.info("Successfully run : '{}'".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            log.info("Failed to run : '{}'".format(result['cmd']))
            pytest.xfail()


@pytest.mark.parametrize("valid_user_cert", ["CA_AdminV", "CA_AgentV", "CA_AuditV"])
def test_pki_ca_kraconnector_add_with_valid_user_cert(valid_user_cert, ansible_module):
    """
    :Title: test for ca-kraconnaector-add  Server side testing
    :Description: Testing ca-kraconnector-add with Valid Administrator,Agent,Operator & UnPrivileged
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :Setup: Use the subsystems and database setup with all certificates in ansible to run subsystem commands
    :Steps:
        1. Run command : pki -p 23080 -d nssdb -c SECret.123
                -n "Valid Certificate" ca-kraconnector-add --host pki1.example.com --port 21080
        2. Remove the valid user cert from kra admin group
    :Expectedresults:
        1. It should show success message
    """
    # add ca karconnector with valid user cert
    cmd_out = ansible_module.pki(cli="ca-kraconnector-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick=valid_user_cert,
                                 extra_args="--host {} --port {}".format(constants.MASTER_HOSTNAME,
                                                                         constants.KRA_HTTP_PORT))
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert "ForbiddenException: Authorization Error" in result['stderr']
            log.info("Successfully run : '{}'".format(result['cmd']))
        else:
            assert result['rc'] == 0
            log.info("Failed to run : '{}'".format(result['cmd']))
            pytest.xfail()


@pytest.mark.parametrize("revoked_user_cert", ["CA_AdminR", "CA_AgentR", "CA_AuditR"])
def test_pki_ca_kraconnector_add_with_revoked_user_cert(revoked_user_cert, ansible_module):
    """
    :Title: test for ca-kraconnaector-add  Server side testing
    :Description: Testing ca-kraconnector-add with Revoked Administrator,Agent,Operator & UnPrivileged
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :Setup: Use the subsystems and database setup with all certificates in ansible to run subsystem commands
    :Steps:
        1. Run command : pki -p 23080 -d nssdb -c SECret.123 -n "Revoked Certificate"
                ca-kraconnector-add --host pki1.example.com --port 21080
    :Expectedresults:
        1. Failed
    """
    # add ca karconnector with revoked user cert
    cmd_out = ansible_module.pki(cli="ca-kraconnector-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick=revoked_user_cert,
                                 extra_args="--host {} --port {}".format(constants.MASTER_HOSTNAME,
                                                                         constants.KRA_HTTP_PORT))
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert "PKIException: Unauthorized" in result['stderr']
            log.info("Successfully run : '{}'".format(result['cmd']))
        else:
            assert result['rc'] == 0
            log.info("Failed to run : '{}'".format(result['cmd']))
            pytest.xfail()


@pytest.mark.parametrize("expired_user_cert", ["CA_AdminE", "CA_AgentE", "CA_AuditE"])
def test_pki_ca_kraconnector_add_with_expired_user_cert(expired_user_cert, ansible_module):
    """
    :Title: test for ca-kraconnaector-add  Server side testing
    :Description: Testing ca-kraconnector-add with Expired Administrator,Agent,Operator & UnPrivileged
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :Setup: Use the subsystems and database setup with all certificates in ansible to run subsystem commands
    :Steps:
        1. Run command : pki -p 23080 -d nssdb -c SECret.123 -n "Expired Certificate"
                ca-kraconnector-add --host pki1.example.com --port 21080
    :Expectedresults:
        1. CLI should failed with Certficate Expired
    """
    # add ca karconnector with Expired user cert
    cmd_out = ansible_module.pki(cli="ca-kraconnector-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick=expired_user_cert,
                                 extra_args="--host {} --port {}".format(constants.MASTER_HOSTNAME,
                                                                         constants.KRA_HTTP_PORT))
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert "CERTIFICATE_EXPIRED" in result['stderr']
            log.info("Successfully run :'{}'".format(result['cmd']))
        else:
            assert result['rc'] == 0
            log.info("Failed to run : '{}'".format(result['cmd']))
            pytest.xfail()


def test_pki_ca_kraconnector_add_with_invalid_user(ansible_module):
    """
    :Title: pki ca-kraconnector-add with invalid user's cert
    :Description: Issue pki ca-kraconnector-add with invalid user
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -u pki_user -w Secret123 ca-kraconnector-add -host pki1.example.com --port 21080
    :Expected results:
        1. It should return an Unauthorised Exception.
    """
    # add the ca kraconnector with invalid user cert
    command_out = ansible_module.pki(cli="ca-kraconnector-add",
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
            pytest.xfail()


def test_pki_ca_kraconnector_add_with_normal_user_cert(ansible_module):
    """
    :Title: pki ca-kraconnector-add with normal user cert
    :Description: Issue pki ca-kraconnector-add with normal user cert should fail
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
    # add normal user
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
    # add normal user to cert
    ansible_module.pki(cli='ca-user-cert-add',
                       nssdb=constants.NSSDB,
                       dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                       port=constants.CA_HTTP_PORT,
                       hostname=constants.MASTER_HOSTNAME,
                       certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                       extra_args='{} --serial {}'.format(user, cert_id))
    # import normal user cert into db
    cert_import = 'pki -d {} -c {} -p {} -h {} client-cert-import "{}" ' \
                  '--serial {}'.format(constants.NSSDB,
                                       constants.CLIENT_DIR_PASSWORD,
                                       constants.CA_HTTPS_PORT,
                                       constants.MASTER_HOSTNAME, user,
                                       cert_id)
    ansible_module.command(cert_import)
    # add ca kraconnector with normal user
    cmd_out = ansible_module.pki(cli="ca-kraconnector-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(user),
                                 extra_args="--host {} --port {}".format(constants.MASTER_HOSTNAME,
                                                                         constants.KRA_HTTP_PORT))
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


def test_pki_ca_kraconnector_add_with_invalid_cert(ansible_module):
    """
    :Title: pki ca-kraconnector-add with invalid cert
    :Description: Issue pki ca-kraconnector-add with invalid cert
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Show kraconnector with invalid cert pki -d certdb -p 20080
                -c SECret.123 -n "Invalid cert" ca-kraconnector-add -host pki1.example.com --port 21080
    :Expected results:
        1. It should return an Forbidden Exception.
    """
    cmd_out = ansible_module.pki(cli="ca-kraconnector-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick="FooBaar",
                                 extra_args="--host {} --port {}".format(constants.MASTER_HOSTNAME,
                                                                         constants.KRA_HTTP_PORT))
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert "Certificate not found: FooBaar" in result['stderr']
            log.info("Successfully run :'{}'".format(result['cmd']))
        else:
            assert result['rc'] == 0
            log.info("Failed to run : '{}'".format(result['cmd']))
            pytest.fail()


def test_pki_ca_kraconnector_add_with_wrong_parameter(ansible_module):
    """
     :Title: test for ca-kraconnaector-add with worng parameter in port and host
     :Description: Testing ca-kraconnector-add with worng parameter
     :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
     :Setup: Use the subsystems and database setup with all certificates in ansible to run subsystem commands
     :Steps:
         1. Run command : pki -p 23080 -d nssdb -c SECret.123 -n "admin cert" ca-kraconnector-add
                --host server.adfadf.adfacom --port abc8443zyz
     :Expectedresults:
         1. It should show error message
     """
    # add user cert with worng host and port
    cmd_out = ansible_module.pki(cli="ca-kraconnector-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                 extra_args="--host {} --port {}".format("server.adfadf.adfacom", "abc8443zyz"))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added KRA host "server.adfadf.adfacom:abc8443zyz"' in result['stdout']
            log.info("Successfully run : '{}'".format(result['cmd']))
            log.info('RH Bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1665176')
        else:
            assert result['rc'] >= 1
            log.info("Failed to run : '{}'".format(result['cmd']))
            pytest.fail()
