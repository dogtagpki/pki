"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: ca-authirty tests for enable cli
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
import random,binascii
from pki.testlib.common.certlib import os,sys,pytest
from pki.testlib.common.utils import ProfileOperations, UserOperations
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

@pytest.mark.parametrize('args', ['--help', binascii.b2a_hex(os.urandom(10))])
def test_pki_ca_authority_enable_help(ansible_module, args):
    """
    :Title: Test pki ca-authority-enable  --help command.
    :Description: test pki ca-authority-enable help command
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
                    -n "PKI CA Administrator for Example.Org" ca-authority-enable --help
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
                    -n "PKI CA Administrator for Example.Org" ca-authority-enable asdf
    :Expected results:
        1. It should return help message.
    """
    cmd_out = ansible_module.pki(cli="ca-authority-enable",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(args))
    for result in cmd_out.values():
        if args == '--help':
            assert result['rc'] == 0
            assert "usage: ca-authority-enable <ID>" in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            assert 'BadRequestException' in result['stderr']
            log.info("Successfully run : '{}'".format(result['cmd']))


def test_pki_ca_authority_enable_when_authority_is_disabled(ansible_module):
    """
    :Title: pki ca-authority-enable when authority is disabled
    :Description: Execute pki ca-authority-enable when authority is disabled
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
                -n "PKI CA Administrator for Example.Org" ca-authority-create testcaUserCert1
                    CN="Authority Name" --parent "Authority ID"
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
                -n "PKI CA Administrator for Example.Org" ca-authority-disable "authority ID"
        3. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
                -n "PKI CA Administrator for Example.Org" ca-authority-enable "authority ID"
    :Expected results:
        1. It should enable the authority
    """
    test_CN = 'test_CN{}'.format(random.randint(1111, 99999999))

    # find the parent authority id
    authority_id_find = ansible_module.pki(cli="ca-authority-show",
                                           nssdb=constants.NSSDB,
                                           dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                           port=constants.CA_HTTP_PORT,
                                           hostname=constants.MASTER_HOSTNAME,
                                           certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                           extra_args='--host-authority')

    for result in authority_id_find.values():
        authority_id = re.findall('ID:.*', result['stdout'])
        authority_id = authority_id[0].split(":")[1].strip()

    # Create the sub authority with help of parent authority id
    cmd_out = ansible_module.pki(cli="ca-authority-create",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                 extra_args="CN='{}' --parent {}".format(test_CN, authority_id))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Authority DN:" in result['stdout']
            assert "ID:" in result['stdout']
            assert "Parent ID:      {}".format(authority_id) in result['stdout']
            assert "Issuer DN:" in result['stdout']
            assert "Serial no:" in result['stdout']
            assert "Enabled:        true" in result['stdout']
            assert "Ready to sign:  true" in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.fail()

    # Search the Sub authority id
    authority_id_find = ansible_module.pki(cli="ca-authority-find",
                                           nssdb=constants.NSSDB,
                                           dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                           port=constants.CA_HTTP_PORT,
                                           hostname=constants.MASTER_HOSTNAME,
                                           certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                           extra_args='--dn "CN={}"'.format(test_CN))
    for result in authority_id_find.values():
        authority_id = re.findall('ID:.*', result['stdout'])
        authority_id = authority_id[0].split(":")[1].strip()

    # Disable the authority
    cmd_out = ansible_module.pki(cli="ca-authority-disable",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                 extra_args="{}".format(authority_id))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Enabled:        false" in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.fail()

    # enable the authority
    cmd_out = ansible_module.pki(cli="ca-authority-enable",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                 extra_args="{}".format(authority_id))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Enabled:        true" in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.fail()


def test_pki_ca_authority_enable_as_non_existing_authority(ansible_module):
    """
    :Title: pki ca-authority-enable as non-existing authority
    :Description: Issue pki ca-authority-enable as non-existing authority should fail
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
                -n "PKI CA Administrator for Example.Org" ca-authority-enable NonExistingauthority
    :Expected results:
        1. It should return a NotFound Exception
    """
    cmd_out = ansible_module.pki(cli="ca-authority-enable",
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


@pytest.mark.parametrize("valid_user_cert", ["CA_AdminV", "CA_AgentV", "CA_AuditV"])
def test_pki_ca_authority_enable_with_valid_user_cert(valid_user_cert, ansible_module):
    """
    :Title: pki ca-authority-enable with different valid user's cert
    :Description: Executing pki ca-authority-enable using valid user cert should pass
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    Create the authority with different valid user's certs
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
                -n "Admin Cert" ca-authority-create testcaUserCert1 CN="Authority Name" --parent "Authority ID"
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
                -n "Admin Cert" ca-authority-disable "authority ID"
        3. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
                -n "CA_AdminV" ca-authority-enable "authority ID"
        4. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
                -n "CA_AgentV" ca-authority-enable "authority ID"
        5. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
                -n "CA_AuditV" ca-authority-enable "authority ID"
    :Expected results:
        1. It should create the authority
        2. It should enable the authority
        3. It should disable the authority with only CA_AdminV.
        4. other certs failed with Authorization ERROR
    """
    test_CN = 'test_CN{}'.format(random.randint(1111, 99999999))

    # Search the parent authority id
    authority_id_find = ansible_module.pki(cli="ca-authority-show",
                                           nssdb=constants.NSSDB,
                                           dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                           port=constants.CA_HTTP_PORT,
                                           hostname=constants.MASTER_HOSTNAME,
                                           certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                           extra_args='--host-authority')

    for result in authority_id_find.values():
        authority_id = re.findall('ID:.*', result['stdout'])
        authority_id = authority_id[0].split(":")[1].strip()

    # Create the sub authority with parent authority id
    cmd_out = ansible_module.pki(cli="ca-authority-create",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                 extra_args="CN='{}' --parent {}".format(test_CN, authority_id))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Authority DN:" in result['stdout']
            assert "ID:" in result['stdout']
            assert "Parent ID:      {}".format(authority_id) in result['stdout']
            assert "Issuer DN:" in result['stdout']
            assert "Serial no:" in result['stdout']
            assert "Enabled:        true" in result['stdout']
            assert "Ready to sign:  true" in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.fail()

    # find the sub authority
    authority_id_find = ansible_module.pki(cli="ca-authority-find",
                                           nssdb=constants.NSSDB,
                                           dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                           port=constants.CA_HTTP_PORT,
                                           hostname=constants.MASTER_HOSTNAME,
                                           certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                           extra_args='--dn "CN={}"'.format(test_CN))
    for result in authority_id_find.values():
        authority_id = re.findall('ID:.*', result['stdout'])
        authority_id = authority_id[0].split(":")[1].strip()

    # Disable the sub authority
    cmd_out = ansible_module.pki(cli="ca-authority-disable",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                 extra_args="{}".format(authority_id))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Enabled:        false" in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.fail()

    # Check to enable the authority with different valid certs
    cmd_out = ansible_module.pki(cli="ca-authority-enable",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='{}'.format(valid_user_cert),
                                 extra_args="{}".format(authority_id))
    for result in cmd_out.values():
        if result['rc'] == 0:
            if valid_user_cert == 'CA_AdminV':
                assert "Authority DN:" in result['stdout']
                assert "ID:             {}".format(authority_id) in result['stdout']
                assert "Parent ID:" in result['stdout']
                assert "Issuer DN:" in result['stdout']
                assert "Serial no:" in result['stdout']
                assert "Enabled:        true" in result['stdout']
                assert "Ready to sign:  true" in result['stdout']
                log.info("Successfully ran : '{}'".format(result['cmd']))
            else:
                log.error("Failed to ran : '{}'".format(result['cmd']))
                pytest.fail()
        else:
            assert 'Authorization Error' in result['stderr']
            log.info("Successfully ran : '{}'".format(result['cmd']))


@pytest.mark.parametrize("revoked_user_cert", ["CA_AdminR", "CA_AgentR", "CA_AuditR"])
def test_pki_ca_authority_enable_with_revoked_user_cert(revoked_user_cert, ansible_module):
    """
    :Title: pki ca-authority-enable with different Revoked user's cert
    :Description: Executing pki ca-authority-enable using Revoked user cert should failed
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    Create the authority with different valid user's certs
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
                -n "Admin Cert" ca-authority-create testcaUserCert1 CN="Authority Name" --parent "Authority ID"
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
                -n "Admin Cert" ca-authority-disable "authority ID"
        3. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
                -n "CA_AdminR" ca-authority-enable "authority ID"
        4. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
                -n "CA_AgentR" ca-authority-enable "authority ID"
        4. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
                -n "CA_AuditR" ca-authority-enable "authority ID"
    :Expected results:
        1. It should create the authority
        2. It should enable the authority
        4. other certs failed with ERROR
    """
    test_CN = 'test_CN{}'.format(random.randint(1111, 99999999))

    # find the parent authority id
    authority_id_find = ansible_module.pki(cli="ca-authority-show",
                                           nssdb=constants.NSSDB,
                                           dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                           port=constants.CA_HTTP_PORT,
                                           hostname=constants.MASTER_HOSTNAME,
                                           certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                           extra_args='--host-authority')
    for result in authority_id_find.values():
        authority_id = re.findall('ID:.*', result['stdout'])
        authority_id = authority_id[0].split(":")[1].strip()

    # Create the sub authority with parent authority id
    cmd_out = ansible_module.pki(cli="ca-authority-create",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                 extra_args="CN='{}' --parent {}".format(test_CN, authority_id))

    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Authority DN:" in result['stdout']
            assert "ID:" in result['stdout']
            assert "Parent ID:      {}".format(authority_id) in result['stdout']
            assert "Issuer DN:" in result['stdout']
            assert "Serial no:" in result['stdout']
            assert "Enabled:        true" in result['stdout']
            assert "Ready to sign:  true" in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.fail()

    # find the sub authority id
    authority_id_find = ansible_module.pki(cli="ca-authority-find",
                                           nssdb=constants.NSSDB,
                                           dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                           port=constants.CA_HTTP_PORT,
                                           hostname=constants.MASTER_HOSTNAME,
                                           certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                           extra_args='--dn "CN={}"'.format(test_CN))
    for result in authority_id_find.values():
        authority_id = re.findall('ID:.*', result['stdout'])
        authority_id = authority_id[0].split(":")[1].strip()

    # disable the sub authority
    cmd_out = ansible_module.pki(cli="ca-authority-disable",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                 extra_args="{}".format(authority_id))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Enabled:        false" in result['stdout']
            log.info("Successfully Run : '{}'".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.fail()

    # enable the sub authority
    cmd_out = ansible_module.pki(cli="ca-authority-enable",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='{}'.format(revoked_user_cert),
                                 extra_args="{}".format(authority_id))
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert "PKIException: Unauthorized" in result['stderr']
            log.info("Successfully Run : '{}'".format(result['cmd']))
        else:
            assert result['rc'] == 0
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.fail()


@pytest.mark.parametrize("expired_user_cert", ["CA_AdminE", "CA_AgentE", "CA_AuditE"])
def test_pki_ca_profile_enable_with_expired_user_cert(expired_user_cert, ansible_module):
    """
    :Title: pki ca-authority-enable with different valid user's cert
    :Description: Executing pki ca-authority-enable using Revoked user cert should failed
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    Create the authority with different valid user's certs
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
                -n "Admin Cert" ca-authority-create testcaUserCert1 CN="Authority Name" --parent "Authority ID"
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
                -n "Admin Cert" ca-authority-disable "authority ID"
        3. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
                -n "CA_AdminE" ca-authority-enable "authority ID"
        4. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
                -n "CA_AgentE" ca-authority-enable "authority ID"
    :Expected results:
        1. It should create the authority
        2. It should enable the authority
        4. other certs failed with ERROR
    """
    test_CN = 'test_CN{}'.format(random.randint(1111, 99999999))

    # find the parent authority id
    authority_id_find = ansible_module.pki(cli="ca-authority-show",
                                           nssdb=constants.NSSDB,
                                           dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                           port=constants.CA_HTTP_PORT,
                                           hostname=constants.MASTER_HOSTNAME,
                                           certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                           extra_args='--host-authority')

    for result in authority_id_find.values():
        authority_id = re.findall('ID:.*', result['stdout'])
        authority_id = authority_id[0].split(":")[1].strip()

    # create the sub authority
    cmd_out = ansible_module.pki(cli="ca-authority-create",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                 extra_args="CN='{}' --parent {}".format(test_CN, authority_id))

    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Authority DN:" in result['stdout']
            assert "ID:" in result['stdout']
            assert "Parent ID:      {}".format(authority_id) in result['stdout']
            assert "Issuer DN:" in result['stdout']
            assert "Serial no:" in result['stdout']
            assert "Enabled:        true" in result['stdout']
            assert "Ready to sign:  true" in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.fail()

    # find the sub authority id
    authority_id_find = ansible_module.pki(cli="ca-authority-find",
                                           nssdb=constants.NSSDB,
                                           dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                           port=constants.CA_HTTP_PORT,
                                           hostname=constants.MASTER_HOSTNAME,
                                           certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                           extra_args='--dn "CN={}"'.format(test_CN))
    for result in authority_id_find.values():
        authority_id = re.findall('ID:.*', result['stdout'])
        authority_id = authority_id[0].split(":")[1].strip()
    # Disable the authority
    cmd_out = ansible_module.pki(cli="ca-authority-disable",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                 extra_args="{}".format(authority_id))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Enabled:        false" in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.fail()
    # Enable the authority with expired certifcate
    cmd_out = ansible_module.pki(cli="ca-authority-enable",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='{}'.format(expired_user_cert),
                                 extra_args="{}".format(authority_id))
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert "CERTIFICATE_EXPIRED" in result['stderr']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] == 0
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.fail()


def test_pki_ca_profile_enable_with_normal_user_cert(ansible_module):
    """
    :Title: pki ca-authority-enable with normal user cert
    :Description: Issue pki ca-authority-enable with normal user cert should fail
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Add User
        2. Generate User Cert
        3. Add Cert to User
        4. Add User cert in database
        5. enable profile using the same user cert
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
    # Add the user
    ansible_module.pki(cli='ca-user-cert-add',
                       nssdb=constants.NSSDB,
                       dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                       port=constants.CA_HTTP_PORT,
                       hostname=constants.MASTER_HOSTNAME,
                       certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                       extra_args='{} --serial {}'.format(user, cert_id))
    # Import the user cert on db
    cert_import = 'pki -d {} -c {} -p {} -h {} client-cert-import "{}" ' \
                  '--serial {}'.format(constants.NSSDB,
                                       constants.CLIENT_DIR_PASSWORD,
                                       constants.CA_HTTPS_PORT,
                                       constants.MASTER_HOSTNAME, user,
                                       cert_id)
    ansible_module.command(cert_import)

    test_CN = 'test_CN{}'.format(random.randint(1111, 99999999))

    # find the root authority DN
    authority_id_find = ansible_module.pki(cli="ca-authority-show",
                                           nssdb=constants.NSSDB,
                                           dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                           port=constants.CA_HTTP_PORT,
                                           hostname=constants.MASTER_HOSTNAME,
                                           certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                           extra_args='--host-authority')

    for result in authority_id_find.values():
        authority_id = re.findall('ID:.*', result['stdout'])
        authority_id = authority_id[0].split(":")[1].strip()

    # Create the authority with admin cert
    cmd_out = ansible_module.pki(cli="ca-authority-create",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                 extra_args="CN='{}' --parent {}".format(test_CN, authority_id))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Authority DN:" in result['stdout']
            assert "ID:" in result['stdout']
            assert "Parent ID:      {}".format(authority_id) in result['stdout']
            assert "Issuer DN:" in result['stdout']
            assert "Serial no:" in result['stdout']
            assert "Enabled:        true" in result['stdout']
            assert "Ready to sign:  true" in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.fail()

    # find the sub authority id
    authority_id_find = ansible_module.pki(cli="ca-authority-find",
                                           nssdb=constants.NSSDB,
                                           dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                           port=constants.CA_HTTP_PORT,
                                           hostname=constants.MASTER_HOSTNAME,
                                           certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                           extra_args='--dn "CN={}"'.format(test_CN))
    for result in authority_id_find.values():
        authority_id = re.findall('ID:.*', result['stdout'])
        authority_id = authority_id[0].split(":")[1].strip()

    # Disable the authority with admin cert
    cmd_out = ansible_module.pki(cli="ca-authority-disable",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                 extra_args="{}".format(authority_id))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Enabled:        false" in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.fail()

    # Enable the sub authority with normal cert
    cmd_out = ansible_module.pki(cli="ca-authority-enable",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(user),
                                 extra_args="{}".format(authority_id))
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert "ForbiddenException" in result['stderr']
            log.info("Successfully run : '{}'".format(result['cmd']))
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
