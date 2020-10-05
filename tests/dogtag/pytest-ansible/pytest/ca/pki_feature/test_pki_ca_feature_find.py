"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: ca-feature tests for find
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
import binascii
try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout)

@pytest.mark.parametrize('args', ['--help', binascii.b2a_hex(os.urandom(10)), ''])
def test_pki_ca_feature_find_help(ansible_module, args):
    """
    :Title: Test pki ca-feature-find  --help command.
    :Description: test pki ca-feature-find --help command
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c
                SECret.123 -n "PKI CA Administrator for Example.Org" ca-feature-find --help
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c
                SECret.123 -n "PKI CA Administrator for Example.Org" ca-feature-find asdf
    :Expected results:
        1. It should return help message.
    """
    cmd_out = ansible_module.pki(cli="ca-feature-find",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(args))
    for result in cmd_out.values():
        if args == '--help':
            assert result['rc'] == 0
            assert "usage: ca-feature-find" in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        elif args == '':
            if result['rc'] == 0:
                assert 'ID:             authority' in result['stdout']
                log.info("Successfully ran : '{}'".format(result['cmd']))
            else:
                log.error("Failed to run : {}".format(result['cmd']))
                pytest.fail()
        else:
            if result['rc'] == 0:
                assert 'ID:             authority' in result['stdout']
                log.info("Successfully ran : '{}'".format(result['cmd']))
            else:
                log.error("Failed to run : {}".format(result['cmd']))
                pytest.fail()

def test_pki_ca_feature_find_as_anonymous_certificate(ansible_module):
    """
    :Title: pki ca-feature-find as anonymous user
    :Description: Execute pki ca-feature-find as anonymous user should fail
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com
           -c SECret.123 ca-feature-find caAgentFoobar
    :Expected results:
        2. It should return Forbidden Exception

    """
    cmd_out = ansible_module.pki(cli="ca-authority-find",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick="anonymous")
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert "Certificate not found: anonymous" in result['stderr']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] == 0
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.fail()

@pytest.mark.parametrize("valid_user_cert", ["CA_AdminV", "CA_AgentV", "CA_AuditV"])
def test_pki_ca_feature_find_with_valid_user_cert(valid_user_cert, ansible_module):
    """
    :Title: pki ca-feature-find with valid user's cert
    :Description: Executing pki ca-feature-find using valid user cert should pass
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
                -n "CA_AdminV" ca-feature-find
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
                -n "CA_AgentV" ca-feature-find
        3. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
                -n "CA_AuditV" ca-feature-find
    :Expected results:
        1. It should return authority detail
    """
    cmd_out = ansible_module.pki(cli="ca-feature-find",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(valid_user_cert))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'ID:             authority' in result['stdout']
            assert 'Description:    Lightweight CAs' in result['stdout']
            assert 'Enabled:        true' in result['stdout']
            assert 'Number of entries returned' in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            pytest.fail()


@pytest.mark.parametrize("revoked_user_cert", ["CA_AdminR", "CA_AgentR", "CA_AuditR"])
def test_pki_ca_feature_find_with_revoked_user_cert(revoked_user_cert, ansible_module):
    """
    :Title: pki ca-feature-find with different revoked user's cert
    :Description: Executing pki ca-feature-find using revoked user cert
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
          -n "CA_AdminR" ca-feature-find
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
          -n "CA_AgentR" ca-feature-find
        3. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
          -n "CA_AuditR" ca-feature-find
    :Expected results:
        1. It should throw an Exception.

    """
    cmd_out = ansible_module.pki(cli="ca-feature-find",
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
            pytest.fail()


@pytest.mark.parametrize("expired_user_cert", ["CA_AdminE", "CA_AgentE", "CA_AuditE"])
def test_pki_ca_feature_find_with_expired_user_cert(expired_user_cert, ansible_module):
    """
    :Title: pki ca-feature-find with different user's expired cert
    :Description: Executing pki ca-feature-find using expired user cert
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "CA_AdminE" ca-feature-find
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "CA_AgentE" ca-feature-find
        3. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -n "CA_AuditE" ca-feature-find
    :Expected results:
        1. It should return an CERTIFICATE UNKNOWN Exception.
    """
    cmd_out = ansible_module.pki(cli="ca-feature-find",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(expired_user_cert))
    for result in cmd_out.values():
        if result['rc'] >= 0:
            assert "CERTIFICATE_EXPIRED" in result['stderr']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] == 1
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.fail()


def test_pki_ca_feature_find_with_invalid_user(ansible_module):
    """
    :Title: pki ca-feature-find with invalid user's cert
    :Description: Issue pki ca-feature-find with invalid user
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -u pki_user -w Secret123 ca-feature-find
    :Expected results:
        1. It should return an Unauthorised Exception.

    """
    command_out = ansible_module.pki(cli="ca-feature-find",
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
            pytest.fail()
