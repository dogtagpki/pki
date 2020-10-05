"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Automation of Bug 1666907 - CC: Enable AIA OCSP cert
#                checking for entire cert chain
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Pritam Singh <prisingh@redhat.com>
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
import logging
import os
import time
import re
import datetime
import random
import sys
import pytest
from pki.testlib.common.utils import UserOperations
from pki.testlib.common.certlib import CertSetup

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

user_op = UserOperations(nssdb=constants.NSSDB)
log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
BASE_DIR = '/var/lib/pki/'
ca_cfg_path = BASE_DIR + '/' + constants.SUBCA_CA_INSTANCE_NAME + '/' + 'ca/conf/CS.cfg'
subca_cfg_path = BASE_DIR + '/' + constants.SUBCA_INSTANCE_NAME + '/' + 'ca/conf/CS.cfg'
kra_cfg_path = BASE_DIR + '/' + constants.SUBCA_KRA_INSTANCE_NAME + '/' + 'ca/conf/CS.cfg'


@pytest.mark.setup
def test_setup(ansible_module):
    """
    It creates NSSDB and import ca.
    """
    cert_setup = CertSetup(nssdb=constants.NSSDB,
                           db_pass=constants.CLIENT_DATABASE_PASSWORD,
                           host='{}'.format(constants.MASTER_HOSTNAME),
                           port=constants.SUBCA_HTTP_PORT,
                           nick="'{}'".format(constants.SUBCA_ADMIN_NICK))
    cert_setup.create_certdb(ansible_module)
    cert_setup.import_ca_cert(ansible_module)
    import_admin_p12 = ansible_module.pki(
        cli='client-cert-import',
        nssdb=constants.NSSDB,
        dbpassword=constants.CLIENT_DATABASE_PASSWORD,
        port=constants.SUBCA_HTTP_PORT,
        extra_args='--pkcs12 /root/.dogtag/{}/ca_admin_cert.p12 '
                   '--pkcs12-password {} '.format(constants.SUBCA_INSTANCE_NAME, constants.CLIENT_PKCS12_PASSWORD))
    for result in import_admin_p12.values():
        assert "Imported certificate" in result['stdout']
        log.info('Imported CA Admin Cert')


def test_setup_for_kra_and_ocsp_aia_extension_check(ansible_module):
    """
    :id: 22cf57fa-1005-4064-986c-1f00cd43e79c
    :Title: Setup KRA pointing to SubCA security domain and check for its AIA extension
    :Description: Setup KRA pointing to SubCA security domain and check for its AIA extension
    :Requirement: PKI FIPS compliance and NSS-based SSLEngine Support
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Install KRA to join SubCA security domain
        2. Check for KRA certs to validate its AIA extension is pointing to SubCA ocsp
    :ExpectedResults:
        1. KRA installation should successful
        2. KRA alias certs AIA  should point to SubCA
    """
    # Setup KRA instance
    kra_conf = '/tmp/test_dir/kra.cfg'
    log.info('Updating KRA config file')
    ansible_module.replace(path=kra_conf, regexp='krapki_https_port', replace=constants.SUBCA_KRA_HTTPS_PORT)
    ansible_module.replace(path=kra_conf, regexp='krapki_http_port', replace=constants.SUBCA_KRA_HTTP_PORT)
    ansible_module.replace(path=kra_conf, regexp='secure_domain_port', replace=constants.SUBCA_HTTPS_PORT)
    ansible_module.replace(path=kra_conf, regexp='topology-SubCA_Foobarmaster.org',
                           replace=constants.SUBCA_SECURITY_DOMAIN_NAME)
    ansible_module.replace(path=kra_conf, regexp='krapki_ajp_port', replace=constants.SUBCA_KRA_AJP_PORT)
    ansible_module.replace(path=kra_conf, regexp='krapki_tomcat_server_port', replace=constants.SUBCA_KRA_TOMCAT_PORT)
    ansible_module.replace(path=kra_conf, regexp=constants.ROOT_CA_CERT_PATH,
                           replace='/var/lib/pki/{}/alias/ca.crt'.format(constants.SUBCA_INSTANCE_NAME))

    log.info('Installing KRA subsystem')
    install_kra = ansible_module.shell('pkispawn -s KRA -f {}'.format(kra_conf))
    for result in install_kra.values():
        assert result['rc'] == 0
        log.info("KRA installed successfully.")

    # Check for AIA Extension in KRA subsystem cert.
    INTERNAL_OCSP_URI = 'http://{}:{}/ca/ocsp'.format(constants.MASTER_HOSTNAME, constants.SUBCA_HTTP_PORT)
    ca_ocsp_uri = 'http://{}:{}/ca/ocsp'.format(constants.MASTER_HOSTNAME, constants.CA_HTTP_PORT)
    internal_pass_file = '/tmp/internal_pass.txt'
    aia_regex = "Name\:\sAuthority\sInformation\sAccess.*\n.*\n.*Location.*\n.*.\n.*"
    instance_db = '/var/lib/pki/{}/alias'.format(constants.SUBCA_KRA_INSTANCE_NAME)
    grep_internal_password = "grep 'internal=' /var/lib/pki/{}/conf/password.conf | cut -d'=' -f2 > {}".format(
        constants.SUBCA_KRA_INSTANCE_NAME, internal_pass_file)
    ansible_module.shell(grep_internal_password)
    find_kra_certs = 'pki -d {} -C {} client-cert-find'.format(instance_db, internal_pass_file)
    cert_names = []
    find_certs = ansible_module.shell(find_kra_certs)
    for result in find_certs.values():
        if result['rc'] == 0:
            nick_list = re.findall("Nickname:.*", result['stdout'])
            for i in nick_list:
                cert_names.append(i.split(":")[1].strip())
        else:
            log.error("Failed to find the certificate nicks")
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail(result['stdout'])
            pytest.fail(result['stderr'])

    for nick in cert_names:
        if not nick.startswith('CA Signing Certificate') and not nick.startswith('CA Subordinate Signing'):
            certutil_cmd = 'certutil -L -d {} -n "{}"'.format(instance_db, nick)
            certutil_out = ansible_module.shell(certutil_cmd)
            for res in certutil_out.values():
                if res['rc'] == 0:
                    aia_ext = re.findall(aia_regex, res['stdout'])
                    for k in aia_ext:
                        try:
                            assert INTERNAL_OCSP_URI in k
                            log.info("Found internal OCSP URI on cert: '{}'".format(nick))
                        except Exception as e:
                            log.info(e)
                            log.error(e)
                            log.error("AIA extension not found for cert : {}".format(nick))
                            pytest.fail()
                else:
                    log.error("AIA extension not found for cert : {}".format(nick))
                    pytest.fail()
        else:
            certutil_cmd = 'certutil -L -d {} -n "{}"'.format(instance_db, nick)
            certutil_out = ansible_module.shell(certutil_cmd)
            for res in certutil_out.values():
                if res['rc'] == 0:
                    aia_ext = re.findall(aia_regex, res['stdout'])
                    for k in aia_ext:
                        try:
                            assert ca_ocsp_uri in k
                            log.info("Found internal OCSP URI on cert: '{}'".format(nick))
                        except Exception as e:
                            log.info(e)
                            log.error(e)
                            log.error("AIA extension not found for cert : {}".format(nick))
                            pytest.fail()
                else:
                    log.error("AIA extension not found for cert : {}".format(nick))
                    pytest.fail()


def test_enable_ocsp_aia_checking_on_subca_subsystem(ansible_module):
    """
    :id: 3edb2c7b-23ab-4de6-85f8-a0f617640f98
    :Title: Test enable OCSP AIA checking on SubCA subsystem
    :Description: Test enable OCSP AIA checking on SubCA subsystem
    :Requirement: PKI FIPS compliance and NSS-based SSLEngine Support
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Modify the changes -
            1.1 Copy the server.xml to /tmp/
            1.2 Make changes to server.xml as enableOCSP='false' to enableOCSP='true' and ocspCacheSize='-1'
            1.3 Remove ocspResponderUrl and ocspResponderNickname parameter
        1. Start the SubCA instance
    :ExpectedResults:
        1. SubCA should start successfully.
    """
    # Modify the changes
    log.info('Modifying the SubCA server.xml')
    server_path = '/var/lib/pki/{}/conf/server.xml'.format(constants.SUBCA_INSTANCE_NAME)
    ansible_module.shell('cp {} {}'.format(server_path, '/tmp/'))
    ansible_module.replace(path=server_path, regexp='enableOCSP="false"', replace='enableOCSP="true"')
    ansible_module.replace(path=server_path, regexp='ocspCacheSize="1000"', replace='ocspCacheSize="-1"')
    ocspResponderUrl_regex = 's/ocspResponderURL=\"http:\/\/{}:{}\/ca\/ocsp\"//g'. \
        format(constants.MASTER_HOSTNAME, constants.SUBCA_HTTP_PORT)
    ocspResponderNick_regex = 's/ocspResponderCertNickname="ocspSigningCert cert-pki-ca"//g'
    ansible_module.command("sed -i '{}' {}".format(ocspResponderUrl_regex, server_path))
    ansible_module.command("sed -i '{}' {}".format(ocspResponderNick_regex, server_path))

    # Change debug log level
    ansible_module.lineinfile(path=ca_cfg_path, regexp="debug.level=10", line="debug.level=5")
    ansible_module.lineinfile(path=subca_cfg_path, regexp="debug.level=10", line="debug.level=5")
    ansible_module.lineinfile(path=kra_cfg_path, regexp="debug.level=10", line="debug.level=5")

    # Restart the Subsystems
    log.info("Restarting CA subsystem")
    ansible_module.command('pki-server restart {}'.format(constants.SUBCA_CA_INSTANCE_NAME))
    log.info("Restarting SubCA")
    ansible_module.command('pki-server restart {}'.format(constants.SUBCA_INSTANCE_NAME))
    log.info('Restarting KRA subsystem')
    ansible_module.command('pki-server restart {}'.format(constants.SUBCA_KRA_INSTANCE_NAME))


def test_trigger_ocsp_lookup_from_ca_to_kra_with_crmf_request(ansible_module):
    """
    :id: 9a279e56-065b-4265-8aab-2934dbe3d9e8
    :Title: Test trigger an actual ocsp lookup by causing the CA to
            contact the KRA, when it attempts to archive a key.
    :Description: Test trigger an actual ocsp lookup by causing the CA to
            contact the KRA, when it attempts to archive a key.
    :Requirement: PKI FIPS compliance and NSS-based SSLEngine Support
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Perform Cert Issuance with CRMF
        2. Approve the cert request
        3. It will generate one entry in the subCA's debug log i.e
        ( kra's server cert getting checked by the subca's ocsp service )
           and one entry in the Root CA's debug log i.e
        ( subca's signing cert getting checked by the Root ca's ocsp service )
    :ExpectedResults:
        1. Cert request should successfully generated with CRMF
        2. Cert request should successfully get approved.
        3. we should see one entry in the subCA's debug log
           and one entry in the Root CA's debug log which creates a chain.
    """
    # CRMF cert request
    subject = "UID=testuser{}".format(random.randint(111, 99999))
    cert_request = ansible_module.pki(cli='client-cert-request',
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.SUBCA_HTTPS_PORT,
                                      certnick='"{}"'.format(constants.SUBCA_ADMIN_NICK),
                                      protocol='https',
                                      extra_args='"{}" --type {}'.format(subject, 'crmf'))
    for result in cert_request.values():
        if result['rc'] == 0:
            assert 'Request Status: pending' in result['stdout']
            request_id = re.search('Request ID: [\w]*', result['stdout'])
            req_id = request_id.group().split(':')[1].strip()
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail('Failed to request cert with crmf')

    # Approve the request
    review_req = ansible_module.pki(cli='ca-cert-request-review',
                                    nssdb=constants.NSSDB,
                                    dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                    certnick="'{}'".format(constants.SUBCA_ADMIN_NICK),
                                    protocol="https",
                                    port=constants.SUBCA_HTTPS_PORT,
                                    extra_args='{} --action {}'.format(req_id, 'approve'))
    for result in review_req.values():
        log.info("Running : {}".format(result['cmd']))
        if result['rc'] == 0:
            assert 'Request Status: complete' in result['stdout']
            assert 'Approved certificate request {}'.format(req_id) in result['stdout']
            log.info('Successfully ran: {}'.format(result['cmd']))
        else:
            assert result['rc'] > 0
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail("Failed to run {}".format(result['cmd']))

    # Find KRA server cert
    internal_pass_file = '/tmp/internal_pass.txt'
    instance_db = '/var/lib/pki/{}/alias'.format(constants.SUBCA_KRA_INSTANCE_NAME)
    grep_internal_password = "grep 'internal=' /var/lib/pki/{}/conf/password.conf | cut -d'=' -f2 > {}".format(
        constants.SUBCA_KRA_INSTANCE_NAME, internal_pass_file)
    ansible_module.shell(grep_internal_password)
    find_kra_certs = 'pki -d {} -C {} client-cert-find'.format(instance_db, internal_pass_file)
    kra_server_cert_name = []
    find_certs = ansible_module.shell(find_kra_certs)
    for result in find_certs.values():
        if result['rc'] == 0:
            nick_list = re.findall("Nickname: Server-Cert.*", result['stdout'])
            for i in nick_list:
                kra_server_cert_name.append(i.split(":")[1].strip())
        else:
            log.error("Failed to find the kra server certificate name")
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail(result['stdout'])
            pytest.fail(result['stderr'])

    kra_cert_serial = []
    for nick in kra_server_cert_name:
        find_kra_serial = 'pki -d {} -C {} client-cert-show "{}"'.format(instance_db,
                                                                         internal_pass_file, nick)
        find_serial = ansible_module.shell(find_kra_serial)
        for result in find_serial.values():
            if result['rc'] == 0:
                kra_serial = re.findall("Serial Number: [\w].*", result['stdout'])
                for i in kra_serial:
                    kra_cert_serial.append(i.split(":")[1].strip())
            else:
                log.error("Failed to find the kra server certificate serial")
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()

    # Find SubCA Signing Cert
    internal_pass_file = '/tmp/internal_pass.txt'
    instance_db = '/var/lib/pki/{}/alias'.format(constants.SUBCA_INSTANCE_NAME)
    grep_internal_password = "grep 'internal=' /var/lib/pki/{}/conf/password.conf | cut -d'=' -f2 > {}".format(
        constants.SUBCA_INSTANCE_NAME, internal_pass_file)
    ansible_module.shell(grep_internal_password)
    find_subca_certs = 'pki -d {} -C {} client-cert-find'.format(instance_db, internal_pass_file)
    subca_signing_cert_name = []
    find_certs = ansible_module.shell(find_subca_certs)
    for result in find_certs.values():
        if result['rc'] == 0:
            nick_list = re.findall("Nickname: caSigningCert.*", result['stdout'])
            for i in nick_list:
                subca_signing_cert_name.append(i.split(":")[1].strip())
        else:
            log.error("Failed to find the subca signing certificate name")
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail(result['stdout'])
            pytest.fail(result['stderr'])

    subca_cert_serial = []
    for nick in subca_signing_cert_name:
        find_subca_serial = 'pki -d {} -C {} client-cert-show "{}"'.format(instance_db,
                                                                           internal_pass_file, nick)
        find_serial = ansible_module.shell(find_subca_serial)
        for result in find_serial.values():
            if result['rc'] == 0:
                subca_serial = re.findall("Serial Number: [\w].*", result['stdout'])
                for i in subca_serial:
                    subca_cert_serial.append(i.split(":")[1].strip())
            else:
                log.error("Failed to find the subca signing certificate serial")
                log.error("Failed to run: {}".format(result['cmd']))
                pytest.fail()

    # Grep the kra server cert serial from subCA's debug log
    date = datetime.datetime.now().strftime("%Y-%m-%d")
    subca_debug_path = '/var/lib/pki/{}/logs/ca/debug.{}.log'.format(constants.SUBCA_INSTANCE_NAME,
                                                                     date)
    cert_serial_find_output = ansible_module.command('tail -n 2000 {}'.format(subca_debug_path))
    for result in cert_serial_find_output.values():
        if result['rc'] == 0:
            raw_serial = re.findall("Serial Number: [\w].*", result['stdout'])
            for no in kra_cert_serial:
                assert 'Serial Number: {}'.format(int(str(no), 16)) in raw_serial
                log.info("Found kra server cert serial no: {} in SubCA's debug log".format(no))
        else:
            log.error("Failed to grep : {}".format(result['cmd']))
            pytest.fail()

    # Grep the SubCA signing cert serial from Root CA's debug log
    rootca_debug_path = '/var/lib/pki/{}/logs/ca/debug.{}.log'.format(constants.SUBCA_CA_INSTANCE_NAME,
                                                                      date)
    cert_serial_find_output = ansible_module.command('tail -n 100 {}'.format(rootca_debug_path))
    for result in cert_serial_find_output.values():
        if result['rc'] == 0:
            raw_serial = re.findall("Serial Number: [\w].*", result['stdout'])
            for no in subca_cert_serial:
                assert 'Serial Number: {}'.format(int(str(no), 16)) in raw_serial
                log.info("Found SubCA's signing cert serial no: {} in Root CA's debug log".format(no))
        else:
            log.error("Failed to grep : {}".format(result['cmd']))
            pytest.fail()


def test_verify_cert_serial_number_for_kra_from_subca_debug_log(ansible_module):
    """
    :id: a386392f-ade5-47dc-91df-1f3fb40a2c92
    :Title: Test Force KRA to check for Internal OCSP URI in SubCA's debug log
    :Description: Test Force KRA to check for Internal OCSP URI in SubCA's debug log
    :Requirement: PKI FIPS compliance and NSS-based SSLEngine Support
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Stop the KRA instance
        2. Modify the changes -
            2.1 Copy the server.xml to /tmp/
            2.2 Make changes to server.xml as enableOCSP='false' to enableOCSP='true'
            2.3 Remove ocspResponderUrl and ocspResponderNickname parameter
        3. Start the KRA instance
        4. Tail on SubCA's debug log
    :ExpectedResults:
        1. SubCA's internal OCSP responder will come to live and log will show KRA subsystem cert's
           which has AIA extension.
    """
    # Modify the changes
    log.info("Modifying KRA's server.xml to enableOCSP='true'")
    server_path = '/var/lib/pki/{}/conf/server.xml'.format(constants.SUBCA_KRA_INSTANCE_NAME)

    ansible_module.shell('cp {} {}'.format(server_path, '/tmp/'))
    ansible_module.replace(dest=server_path, regexp='enableOCSP="false"',
                           replace='enableOCSP="true"')
    ansible_module.replace(path=server_path, regexp='ocspCacheSize="1000"', replace='ocspCacheSize="-1"')
    ocspResponderUrl_regex = 's/ocspResponderURL=\"http:\/\/{}:{}\/ca\/ocsp\"//g'. \
        format(constants.MASTER_HOSTNAME, constants.SUBCA_KRA_HTTP_PORT)
    ocspResponderNick_regex = 's/ocspResponderCertNickname="ocspSigningCert cert-pki-ca"//g'
    ansible_module.command("sed -i '{}' {}".format(ocspResponderUrl_regex, server_path))
    ansible_module.command("sed -i '{}' {}".format(ocspResponderNick_regex, server_path))
    internal_pass_file = '/tmp/internal_pass.txt'
    instance_db = '/var/lib/pki/{}/alias'.format(constants.SUBCA_KRA_INSTANCE_NAME)
    grep_internal_password = "grep 'internal=' /var/lib/pki/{}/conf/password.conf | cut -d'=' -f2 > {}".format(
        constants.SUBCA_KRA_INSTANCE_NAME, internal_pass_file)
    ansible_module.shell(grep_internal_password)

    # Find KRA subsystem's cert name
    log.info('Finding KRA subsystem cert nicknames')
    cert_names = []
    find_kra_certs = 'pki -d {} -C {} client-cert-find'.format(instance_db, internal_pass_file)
    find_certs = ansible_module.shell(find_kra_certs)
    for result in find_certs.values():
        if result['rc'] == 0:
            nick_list = re.findall("Nickname:.*", result['stdout'])
            for i in nick_list:
                cert_names.append(i.split(":")[1].strip())
        else:
            log.error("Failed to find the certificate nicks")
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.fail()

    # Find KRA subsystem's cert serial from nickname except
    # auditSigningCert, ca signing & subca signing certs
    log.info('Finding KRA certs serial number')
    cert_serial = []
    subca_signing_serial = []
    for nick in cert_names:
        if not nick.startswith('auditSigningCert') and not nick.startswith('CA Signing Certificate') and \
                not nick.startswith('CA Subordinate Signing'):
            find_kra_serial = 'pki -d {} -C {} client-cert-show "{}"'.format(instance_db,
                                                                             internal_pass_file, nick)
            find_serials = ansible_module.shell(find_kra_serial)
            for result in find_serials.values():
                if result['rc'] == 0:
                    serial_list = re.findall("Serial Number: [\w].*", result['stdout'])
                    for i in serial_list:
                        cert_serial.append(i.split(":")[1].strip())
                else:
                    log.error("Failed to find the certificate serials")
                    log.error("Failed to run: {}".format(result['cmd']))
                    pytest.fail()
        elif nick.startswith('CA Subordinate Signing'):
            find_subca_serial = 'pki -d {} -C {} client-cert-show "{}"'.format(instance_db,
                                                                               internal_pass_file, nick)
            log.info('Finding SubCA signing cert serial number')
            find_serials = ansible_module.shell(find_subca_serial)
            for result in find_serials.values():
                if result['rc'] == 0:
                    serial_list = re.findall("Serial Number: [\w].*", result['stdout'])
                    for i in serial_list:
                        subca_signing_serial.append(i.split(":")[1].strip())
                else:
                    log.error("Failed to find the certificate serials")
                    log.error("Failed to run: {}".format(result['cmd']))
                    pytest.fail()

    # Start the KRA
    log.info('Starting KRA subsystem')
    ansible_module.command('pki-server restart {}'.format(constants.SUBCA_KRA_INSTANCE_NAME))
    time.sleep(20)

    # Grep the cert serials from SubCA's debug log
    date = datetime.datetime.now().strftime("%Y-%m-%d")
    debug_path = '/var/lib/pki/{}/logs/ca/debug.{}.log'.format(constants.SUBCA_INSTANCE_NAME, date)
    cert_serial_find_output = ansible_module.command('tail -n 1000 {}'.format(debug_path))
    for result in cert_serial_find_output.values():
        if result['rc'] == 0:
            raw_serial = re.findall("Serial Number: [\w].*", result['stdout'])
            for no in cert_serial:
                assert 'Serial Number: {}'.format(int(str(no), 16)) in raw_serial
                log.info("Found kra certs serial no: {} in SubCA's debug log".format(no))
        else:
            log.error("Failed to grep : {}".format(result['cmd']))
            pytest.fail()

    # Grep the cert serials from debug log of Root CA
    debug_path = '/var/lib/pki/{}/logs/ca/debug.{}.log'.format(constants.SUBCA_CA_INSTANCE_NAME,
                                                               date)
    cert_serial_find_output = ansible_module.command('tail -n 300 {}'.format(debug_path))
    for result in cert_serial_find_output.values():
        if result['rc'] == 0:
            raw_serial = re.findall("Serial Number: [\w].*", result['stdout'])
            for no in subca_signing_serial:
                assert 'Serial Number: {}'.format(int(str(no), 16)) in raw_serial
                log.info("Found SubCA's signing cert serial no: {} in RootCA's debug log".format(no))
        else:
            log.error("Failed to grep : {}".format(result['cmd']))
            pytest.fail()

    # Clean up
    ansible_module.command('rm -rf {} {}'.format(internal_pass_file, '/tmp/server.xml'))
