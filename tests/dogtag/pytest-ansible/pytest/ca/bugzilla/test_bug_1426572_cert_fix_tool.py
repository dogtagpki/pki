#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Bug 1426572 - pki-core:10.6/pki-core: various flaws
#                Automate cert-fix tool for CA instance
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Chandan Pinjani<cpinjani@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2020 Red Hat, Inc. All rights reserved.
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

import os
import time
import sys
import re
import logging
import pytest

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

instance = constants.CA_INSTANCE_NAME
instance_name = "-".join(constants.CA_INSTANCE_NAME.split("-")[:-1])
profile = "caServerCert"
certs = ['CA Audit Signing Certificate', 'Subsystem Certificate', 'CA OCSP Signing Certificate', constants.MASTER_HOSTNAME]
BASE_DIR = '/var/lib/pki/'
LDAP_DIR = '/etc/openldap/ldap.conf'
admin_profile = '/usr/share/pki/ca/conf/rsaAdminCert.profile'
profile_cfg_path = BASE_DIR + instance + '/ca/profiles/ca/{}.cfg'.format(profile)
ds_ca_cert = '/etc/dirsrv/slapd-{}-testingmaster/ca.crt'.format(instance_name)

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)


def restart_instance(ansible_module, instance=instance):
    command = 'systemctl restart pki-tomcatd@{}'.format(instance)
    time.sleep(10)
    out = ansible_module.command(command)
    for res in out.values():
        assert res['rc'] == 0


@pytest.fixture(autouse=True)
def setup_fixture(ansible_module):
    """
        :Title: CA Cert-fix: Test Setup
        :Description: This is test for setup creation to run Cert-fix tool
        :Steps:
            1. Create a config files for LDAP install on port 389 & CA install
            2. Install LDAP and CA using modified config files
            3. Modify caServerCert profile to issue certificates expiring in 1000 days
        :Expected Results:
           1. LDAP & CA installed successfully
           2. caServerCert profile range modified successfully
        """
    ansible_module.command('cp -R /tmp/test_dir/ /tmp/test_conf')
    ansible_module.lineinfile(path=admin_profile, regexp="2.default.params.range=720", line="2.default.params.range=1000")
    ansible_module.replace(dest='/tmp/test_conf/ldap.cfg',
                           regexp='^port.*',
                           replace='port = 389')
    ansible_module.replace(dest='/tmp/test_conf/ca.cfg',
                           regexp='pki_ds_ldap_port.*',
                           replace='pki_ds_ldap_port = 389')
    install_ds = ansible_module.shell('dscreate from-file /tmp/test_conf/ldap.cfg')
    for result in install_ds.values():
        assert result['rc'] == 0
        log.info("Setup DS instance.")

    install_ca = ansible_module.shell('pkispawn -s CA -f /tmp/test_conf/ca.cfg')
    for result in install_ca.values():
        assert result['rc'] == 0
        log.info("CA Installed successfully")

    ansible_module.lineinfile(path=profile_cfg_path, regexp="policyset.serverCertSet.2.constraint.params.range=720", line="policyset.serverCertSet.2.constraint.params.range=1000")
    ansible_module.lineinfile(path=profile_cfg_path, regexp="policyset.serverCertSet.2.default.params.range=720", line="policyset.serverCertSet.2.default.params.range=1000")
    ansible_module.lineinfile(path=LDAP_DIR, line="TLS_REQCERT  allow")
    restart_instance(ansible_module)
    log.info("Restarted instance : {}".format(instance))

    out = ansible_module.shell("date")
    cur_clock = out.values()[0]['stdout']

    yield

    #teardown
    log.info("Removing CA instance.")
    res = ansible_module.command('pkidestroy -s CA -i {}'.format(constants.CA_INSTANCE_NAME))
    for res in res.values():
        assert res['rc'] == 0
        log.info("Removed CA instance.")

    log.info("Removing ldap instance.")
    res = ansible_module.command('dsctl slapd-{}-testingmaster remove --do-it'.format(instance_name))
    for res in res.values():
        assert res['rc'] == 0
        log.info("Removed ldap instance.")
    ansible_module.shell('rm -rf /tmp/test_conf/ /tmp/nssdb')

    cmd = "chronyc -a -m 'settime {} + 60 seconds' 'makestep' 'manual reset' 'online'".format(cur_clock)
    out = ansible_module.shell(cmd)
    for result in out.values():
        if result['rc'] == 0:
            log.info("Successfully restored system date")
        else:
            pytest.fail("Failed to run: {}".format("".join(result['cmd'])))

@pytest.mark.skipif("instance_name != 'topology-00'")
@pytest.mark.ansible_playbook_setup('ldap_ca.yml')
def test_bug_1426572(ansible_playbook, ansible_module):
    """
    :id: b59f8f13-303b-4439-b93c-59a7a4e5e010
    :Title: Bug 1426572 - pki-core:10.6/pki-core: various flaws
    :Description: Bug 1426572 - Automate cert-fix tool for CA instance
    :Requirement: RHCS-REQ pki server
    :CaseComponent: \-
    :Setup:
        1. Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Install LDAP on port 389, Install CA
        2. Change caServerCert profile cert range to 1000 days
        3. Configure LDAP Server-Cert trusted by CA
        4. Check Subsystem Certificate status as Valid
        5. Change date to expire certificates except CA signing certificate and DS Server-Cert
        6. Restart CA instance
        7. Check Subsystem Certificate status as Expired
        8. Execute pki-server cert-fix command to renew expired system certificates
        9. Check Subsystem Certificate status as Valid
    :ExpectedResults:
        1. Before cert-fix, ca-cert-find command should show all the old system certificates as expired
        2. After cert-fix command execution, ca instance should be running.
        3. ca-cert-find command should show all the new system certificates as valid
    """

    for cert in certs:
        out = ansible_module.shell('echo "y" | pki -p {} ca-cert-find --name "{}"'.format(constants.CA_HTTPS_PORT, cert))
        for result in out.values():
            if result['rc'] == 0:
                assert 'VALID' in result['stdout']
                log.info("CN={} is Valid".format(cert))
            else:
                log.error(result['stderr'])
                pytest.fail("Failed to run: {}".format("".join(result['cmd'])))

    out = ansible_module.shell("chronyc -a 'manual on' ; chronyc -a -m 'offline' 'settime + 2 year' 'makestep' 'manual reset'")
    for result in out.values():
        if result['rc'] == 0:
            log.info("Successfully changed system date ahead by 2 years")
        else:
            pytest.fail("Failed to run: {}".format("".join(result['cmd'])))

    restart_instance(ansible_module)
    log.info("Restarted instance : {}".format(instance))

    for cert in certs:
        out = ansible_module.shell('pki -p {} ca-cert-find --name "{}"'.format(constants.CA_HTTPS_PORT, cert))
        for result in out.values():
            if result['rc'] >= 1:
                assert "EXPIRED_CERTIFICATE" in result['stderr']
                log.info("CN={} has Expired".format(cert))
            else:
                log.error(result['stderr'])
                pytest.fail("Failed to run: {}".format("".join(result['cmd'])))

    msg = 'INFO: Starting the instance with renewed certs'
    cmd = 'pki-server cert-fix --ldap-url ldap://{}:389 --agent-uid caadmin -i {} -p {}'.format(constants.MASTER_HOSTNAME, instance, constants.CA_HTTPS_PORT)
    out = ansible_module.expect(command=cmd, timeout=300, responses={"Enter Directory Manager password:": "{}".format(constants.LDAP_PASSWD)})
    for result in out.values():
        if 'failed' not in result:
            assert msg in result['stdout']
            log.info("Cert-fix completed successfully")
        else:
            log.error(result['msg'])
            pytest.fail("Failed to run: {}".format("".join(result['cmd'])))

    for cert in certs:
        out = ansible_module.shell('echo "y" | pki -p {} ca-cert-find --name "{}"'.format(constants.CA_HTTPS_PORT, cert))
        for result in out.values():
            if result['rc'] == 0:
                assert 'VALID' in result['stdout']
                log.info("CN={} is Valid".format(cert))
            else:
                log.error(result['stderr'])
                pytest.fail("Failed to run: {}".format("".join(result['cmd'])))

    ansible_module.shell('rm -rf /tmp/nssdb')
    tmp_nssdb = '/tmp/nssdb'
    ansible_module.command('pki -d {} -c {} client-init --force'.format(tmp_nssdb, constants.CLIENT_DATABASE_PASSWORD))
    log.info("Initialized client dir: {}".format(tmp_nssdb))
    command = 'pki -d {} -c {} -p {} client-cert-import --ca-server RootCA'.format(tmp_nssdb, constants.CLIENT_DATABASE_PASSWORD, constants.CA_HTTPS_PORT)
    cert_res = ansible_module.expect(command=command, responses={"Trust this certificate (y/N)?": "y"})
    for result in cert_res.values():
        if result['rc'] == 0:
            log.info("Imported RootCA cert")
        else:
            log.error(result['msg'])
            pytest.fail("Failed to run: {}".format("".join(result['cmd'])))

    cmd = ansible_module.command('pki -d {} -c {} client-cert-import --pkcs12 {} --pkcs12-password {}'.format(tmp_nssdb, constants.CLIENT_DATABASE_PASSWORD, constants.CA_CLIENT_DIR + "/ca_admin_cert.p12", constants.CLIENT_PKCS12_PASSWORD))
    for result in cmd.values():
        if result['rc'] == 0:
            assert 'Imported certificates from PKCS #12 file' in result['stdout']
            log.info('Successfully imported CA Admin cert')
        else:
            log.error(result['stderr'])
            pytest.fail('Failed to import CA Admin Cert')

    # Perform Cert request
    cert_request = ansible_module.command('pki -d {} -c {} -p {} client-cert-request "uid={}"'.format(tmp_nssdb, constants.CLIENT_DATABASE_PASSWORD, constants.CA_HTTPS_PORT, 'testcert'))
    for result in cert_request.values():
        if result['rc'] == 0:
            assert 'Request Status: pending' in result['stdout']
            request_id = re.search('Request ID: [\w]*', result['stdout'])
            req_id = request_id.group().split(':')[1].strip()
            log.info("Certificate Request ID: {}".format(req_id))
        else:
            log.error(result['stderr'])
            pytest.fail('Failed to request cert')

    # Approve cert request
    cmd = 'pki -d {} -c {} -p {} -n "{}" ca-cert-request-approve {}'.format(tmp_nssdb, constants.CLIENT_DATABASE_PASSWORD, constants.CA_HTTPS_PORT, constants.CA_ADMIN_NICK, req_id)
    cert_res = ansible_module.expect(command=cmd, responses={"Are you sure (y/N)?": "y"})
    for result in cert_res.values():
        if result['rc'] == 0:
            cert_id = re.findall(r'Certificate ID: [\w]*', result['stdout'])[0]
            cert_id = cert_id.split(":")[1].strip()
            assert 'Approved certificate request {}'.format(req_id) in result['stdout']
            assert 'Request Status: complete' in result['stdout']
            log.info("Successfully approved request: '{}'".format(req_id))
        else:
            assert result['rc'] > 0
            log.error(result['msg'])
            pytest.fail("Failed to run {}".format(result['cmd']))

    cmd = ansible_module.shell('pki -d {} -c {} -p {} -n "{}" ca-cert-show {}'.format(tmp_nssdb, constants.CLIENT_DATABASE_PASSWORD, constants.CA_HTTPS_PORT, constants.CA_ADMIN_NICK, cert_id))
    for result in cmd.values():
        if result['rc'] == 0:
            assert "VALID" in result['stdout']
            log.info("Successfully ran: '{}'".format(result['cmd']))
        else:
            log.error(result['stderr'])
            pytest.fail('Failed to show cert details')