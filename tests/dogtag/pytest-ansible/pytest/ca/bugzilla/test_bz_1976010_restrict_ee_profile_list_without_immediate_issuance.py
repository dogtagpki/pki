#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Automation of Bz_1976010: Restrict EE profile list and
#                enrollment submission per LDAP group without immediate issuance
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   Author: Pritam Singh <prisingh@redhat.com>
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   Copyright Red Hat, Inc.
#   SPDX-License-Identifier: GPL-2.0-or-later
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""

import logging
import os
import sys
import pytest
import time

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

topology = constants.CA_INSTANCE_NAME.split("-")[1].strip()
instance_name = constants.CA_INSTANCE_NAME
ca_config_path = '/var/lib/pki/{}/ca/conf/CS.cfg'.format(constants.CA_INSTANCE_NAME)
ca_profile_path = '/var/lib/pki/{}/ca/profiles/ca/caDirUserCert.cfg'.format(constants.CA_INSTANCE_NAME)


@pytest.mark.skipif('topology != "00"')
@pytest.fixture(autouse=True)
def topo00_setup_for_ldap_and_ca(ansible_module):
    """
    :id: 90f34de5-a5b8-469c-ab28-73bc0e08638e
    :Title: Topology-00 setup for ldap, ca
    :Description: setup ldap, ca
    :Requirement: RHCS-REQ Certificate Authority Administration
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Install Ldap server
        2. Install CA
        3. Remove CA
        4. Remove LDAP
    :ExpectedResults:
        1. It should install and remove ldap, ca
    :Automated: yes
    """
    # Setup DS instance
    ansible_module.command('cp -R /tmp/test_dir/ /tmp/test_conf')
    log.info('Installing DS')
    out = ansible_module.shell('dscreate from-file /tmp/test_conf/ldap.cfg')
    for result in out.values():
        assert result['rc'] == 0
        log.info("Setup DS instance.")

    # Setup CA instance
    log.info('Installing CA')
    install_ca = ansible_module.shell('pkispawn -s CA -f /tmp/test_conf/ca.cfg')
    for result in install_ca.values():
        assert result['rc'] == 0
        log.info("CA Installed successfully")


    # Create NSSDB and import certificates

    ansible_module.command('pki -d {} -c {} client-init '
                               '--force'.format(constants.NSSDB, constants.CLIENT_DATABASE_PASSWORD))
    log.info("Initialize client dir: {}".format(constants.NSSDB))
    command = 'pki -d {} -c {} -p {} client-cert-import --ca-server'.format(constants.NSSDB,
                                                                                   constants.CLIENT_DATABASE_PASSWORD,
                                                                                   constants.CA_HTTPS_PORT)
    ansible_module.expect(command=command,responses={"Trust this certificate (y/N)?": "y"})
    log.info("Imported RootCA cert.")

    ansible_module.command('pki -d {} -c {} client-cert-import --pkcs12 {} '
                               '--pkcs12-password {}'.format(constants.NSSDB, constants.CLIENT_DATABASE_PASSWORD,
                                                             constants.CA_CLIENT_DIR + "/ca_admin_cert.p12",
                                                             constants.CLIENT_PKCS12_PASSWORD))
    log.info("Imported CA Admin Cert.")


    yield

    # Remove CA instance
    log.info('Removing CA')
    remove_ca = ansible_module.shell('pkidestroy -s CA -i {} --remove-logs'.format(constants.CA_INSTANCE_NAME))
    for result in remove_ca.values():
        assert result['rc'] == 0
        log.info("CA removed successfully.")
        time.sleep(5)

    # Remove Ldap server
    log.info('Removing DS')
    remove_ldap = ansible_module.shell('dsctl topology-00-testingmaster remove --do-it')
    for result in remove_ldap.values():
        assert result['rc'] == 0
        log.info("LDAP removed successfully.")
    ansible_module.command('rm -rf {}'.format(constants.NSSDB))


@pytest.mark.skipif('topology != "00"')
def test_bz_1976010_restrict_ee_profile_list_without_immediate_issuance(ansible_module):
    """
    :id: db9da98e-a707-4603-97d5-146b26e51a1e
    :Title: Test bz 1976010: Restrict EE profile list without immediate issuance
    :Description: Test bz 1976010: Restrict EE profile list without immediate issuance
    :Requirement: RHCS-REQ Certificate Authority Administration
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Create group 'requestors'
        2. Create user 'reqUser1'
        3. Add 'reqUser1' user to 'requestors' group
        4. Add LDAP authentication configuration in CS.cfg
        5. Add 'auth.explicitApprovalRequired=true' and 'authz.acl=group=requestors' lines for LDAP authentication for the LDAP group requestors in caDirUserCert.cfg profile
        6. Restart the CA subsystem
        7. Create the certificate request with user 'reqUser1' which is a group member of the 'requestors' group
        8. Create a certificate request with user 'caadmin' which is not a member of 'requestors' group
    :ExpectedResults:
        1. No automatic certificate issuance
        2. The certificate request status should be 'pending'
    :Automated: yes
    :customerscenario: yes
    """
    # Create group 'requestors'
    group_name = "requestors"
    cmd_out = ansible_module.pki(cli="ca-group-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 protocol='https',
                                 port=constants.CA_HTTPS_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(group_name))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added group "{}"'.format(group_name) in result['stdout']
            assert 'Group ID: {}'.format(group_name) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail("Failed to run : {}".format(result['cmd']))

    # Create user 'reqUser1'
    user_name = "reqUser1"
    cmd_out = ansible_module.pki(cli="ca-user-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 protocol='https',
                                 port=constants.CA_HTTPS_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{} --fullName "{}" --password {}'.format(
                                     user_name, user_name, constants.CA_PASSWORD))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added user "{}"'.format(user_name) in result['stdout']
            assert 'User ID: {}'.format(user_name) in result['stdout']
            assert 'Full name: {}'.format(user_name) in result['stdout']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail('Failed to run: {}'.format(result['cmd']))

    # Add 'reqUser1' user to 'requestors' group
    cmd_out = ansible_module.pki(cli="ca-group-member-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 protocol='https',
                                 port=constants.CA_HTTPS_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='"{}" {}'.format(group_name, user_name))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Added group member "{}"'.format(user_name) in result['stdout']
            assert 'User: {}'.format(user_name) in result['stdout']
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail("Failed to ran : {}".format(result['cmd']))

    # Add LDAP authentication configuration in CS.cfg

    ldap_conf = ['auths.instance.UserDirEnrollment.dnpattern=uid=$attr.uid,ou=people,o={}-CA'.format(constants.CA_INSTANCE_NAME),
             'auths.instance.UserDirEnrollment.ldap.basedn=ou=people,o={}-CA'.format(constants.CA_INSTANCE_NAME),
             'auths.instance.UserDirEnrollment.ldap.ldapconn.host={}'.format(constants.MASTER_HOSTNAME),
             'auths.instance.UserDirEnrollment.ldap.ldapconn.port={}'.format(constants.LDAP_PORT),
             'auths.instance.UserDirEnrollment.ldap.ldapconn.secureConn=false',
             'auths.instance.UserDirEnrollment.ldap.ldapconn.version=3',
             'auths.instance.UserDirEnrollment.ldap.maxConns=',
             'auths.instance.UserDirEnrollment.ldap.minConns=',
             'auths.instance.UserDirEnrollment.ldapByteAttributes=',
             'auths.instance.UserDirEnrollment.ldapStringAttributes=uid,cn,mail',
             'auths.instance.UserDirEnrollment.pluginName=UidPwdDirAuth']

    param = ['auth.explicitApprovalRequired=true',
             'authz.acl=group=requestors']

    for i in ldap_conf:
        ansible_module.lineinfile(path=ca_config_path, insertafter='^auths._002=', line=i)
    for k in param:
        ansible_module.lineinfile(path=ca_profile_path, insertafter='^auth.instance_id', line=k)
    log.info('Successfully added LDAP authentication configuration')

    # Restart the CA subsystem
    ansible_module.command('pki-server restart {}'.format(constants.CA_INSTANCE_NAME))
    time.sleep(5)

    # Create the certificate request with user 'reqUser1'
    cmd = 'pki -d {} -c {} -U http://{}:{} client-cert-request uid={} --profile=caDirUserCert --algorithm rsa ' \
          '--length 2048 --type pkcs10 --username {} --password'.format(constants.NSSDB,
                                                                        constants.CLIENT_DATABASE_PASSWORD,
                                                                        constants.MASTER_HOSTNAME,
                                                                        constants.CA_HTTP_PORT,
                                                                        user_name, user_name)
    cmd_out = ansible_module.expect(command=cmd,
                                    responses={"Password:": "{}".format(constants.CA_PASSWORD)})
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Operation Result: success' in result['stdout']
            assert 'Type: enrollment' in result['stdout']
            assert 'Request Status: pending' in result['stdout']
            log.info('Successfully submitted the certificate request with no automated issuance')
        else:
            log.error(result['stderr'])
            log.error(result['stdout'])
            pytest.fail('Failed to run: {}'.format(result['cmd']))

    # Create the certificate request with user 'caadmin'
    cmd = 'pki -d {} -c {} -U http://{}:{} client-cert-request uid={} --profile=caDirUserCert --algorithm rsa ' \
          '--length 2048 --type pkcs10 --username {} --password'.format(constants.NSSDB,
                                                                        constants.CLIENT_DATABASE_PASSWORD,
                                                                        constants.MASTER_HOSTNAME,
                                                                        constants.CA_HTTP_PORT,
                                                                        'caadmin', 'caadmin')
    cmd_out = ansible_module.expect(command=cmd,
                                    responses={"Password:": "{}".format(constants.CA_PASSWORD)})
    for result in cmd_out.values():
        if result['rc'] > 0:
            assert 'Authorization failed: Authorization failed on resource: group=requestors, operation: {1}' in result['stdout']
            log.info('Failed to submit the request for non group member user')
        else:
            assert 'Operation Result: success' in result['stdout']
            assert 'Request Status: pending' in result['stdout']
            pytest.fail('Failed to run: {}'.format(result['cmd']))

