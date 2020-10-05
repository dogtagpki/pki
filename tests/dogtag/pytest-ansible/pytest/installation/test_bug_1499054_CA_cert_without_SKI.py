"""
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 #
 #   Description: Tests for BZ-1499054 - CA cert without SKI causes
                  issuance failure.
 # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 #
 #   Author: Amol Kahat <akahat@redhat.com>
 #
 # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 #
 #   Copyright (c) 2016 Red Hat, Inc. All rights reserved.
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
import re
import shutil
import sys
import tempfile

import configparser
import pytest

from pki.testlib.common.certlib import CertSetup

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

temp_dir = tempfile.mkdtemp(suffix="_test", prefix='profile_', dir="/tmp/")
log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
topology = constants.CA_INSTANCE_NAME.split("-")[-2]


@pytest.fixture(scope="function")
def setup_ca(ansible_module):
    ver = None
    latest_version = False
    partial_install = False
    request_id = None
    cert_id = None
    copied_1 = []
    step1_cfg = 'ca-external-step1.cfg'
    step2_cfg = 'ca-external-step2.cfg'

    step1_cfg_path = os.path.join(temp_dir, step1_cfg)
    step2_cfg_path = os.path.join(temp_dir, step2_cfg)

    cert_setup = CertSetup(nssdb=temp_dir,
                           db_pass=constants.CLIENT_DATABASE_PASSWORD,
                           host=constants.MASTER_HOSTNAME,
                           port=constants.CA_HTTP_PORT,
                           nick="'{}'".format(constants.CA_ADMIN_NICK))
    ansible_module.command("pki -d {} -c {} client-init "
                           "--force".format(temp_dir, constants.CLIENT_DATABASE_PASSWORD))
    cert_setup.import_ca_cert(ansible_module)
    cert_setup.import_admin_p12(ansible_module, 'ca')

    rpm_version = ansible_module.command('rpm -qi pki-ca | grep Version')
    for res in rpm_version.values():
        ver = re.findall(r"Version*[\w].*", res['stdout'])[0]
        ver = ver.split(":")[1].strip().decode()
    config = configparser.ConfigParser()
    log.info("pki-core version: {}".format(ver))
    if ver:
        if ver > "10.4":
            latest_version = True

    config['DEFAULT'] = {
        'pki_instance_name': 'ExternalCA',
        'pki_http_port': '26080',
        'pki_https_port': '26443',
        'pki_token_password': '{}'.format(constants.CLIENT_DATABASE_PASSWORD),
        'pki_backup_keys': 'True',
        'pki_backup_password': '{}'.format(constants.CLIENT_DATABASE_PASSWORD),
        'pki_hostname': constants.MASTER_HOSTNAME,
        'pki_security_domain_name': constants.CA_SECURITY_DOMAIN_NAME,
        'pki_security_domain_password': '{}'.format(constants.CLIENT_DATABASE_PASSWORD),
        'pki_client_dir': '/opt/ExternalCA',
        'pki_client_database_password': '{}'.format(constants.CLIENT_DATABASE_PASSWORD),
        'pki_client_pkcs12_password': '{}'.format(constants.CLIENT_DATABASE_PASSWORD),
        'pki_client_database_purge': 'False',
        'pki_ds_ldap_port': constants.LDAP_PORT,
        'pki_ds_password': '{}'.format(constants.CLIENT_DATABASE_PASSWORD),
        'pki_sslserver_key_type': 'rsa',
        'pki_sslserver_key_algorithm': 'SHA512withRSA',
        'pki_sslserver_key_size': '2048',
        'pki_subsystem_key_type': 'rsa',
        'pki_subsystem_key_algorithm': 'SHA512withRSA',
        'pki_subsystem_key_size': '2048'}

    config['TOMCAT'] = {
        'pki_ajp_port': '26009',
        'pki_tomcat_server_port': '26005'}

    config['CA'] = {
        'pki_admin_name': 'caadmin',
        'pki_admin_uid': 'caadmin',
        'pki_admin_password': '{}'.format(constants.CLIENT_DATABASE_PASSWORD),
        'pki_admin_nickname': 'caadmin',
        'pki_admin_email': 'caadmin@example.com',

        'pki_external': 'True',
        'pki_external_step_two': 'False',
    }

    if latest_version:
        config['CA']['pki_ca_signing_csr_path'] = '/root/ca_signing.csr'
    else:
        config['CA']['pki_external_csr_path'] = '/root/ca_signing.csr'

    with open(step1_cfg_path, 'w') as configfile:
        config.write(configfile)

    config['CA']['pki_external_step_two'] = "True"
    if latest_version:
        config['CA']['pki_ca_signing_cert_path'] = '/root/ca_signing.crt'
        config['CA']['pki_cert_chain_path'] = '/root/cert_chain.p7b'
    else:
        config['CA']['pki_external_ca_cert_path'] = '/root/ca_signing.crt'
        config['CA']['pki_external_ca_cert_chain_path'] = '/root/cert_chain.p7b'

    with open(step2_cfg_path, 'w') as configfile:
        config.write(configfile)
    for path, file in zip([step1_cfg_path, step2_cfg_path], [step1_cfg, step2_cfg]):
        log.info("Copying file to remote machine: {}".format(file))
        ansible_module.copy(src=path, dest='/root/')
        status = ansible_module.stat(path='/root/{}'.format(file))
        for res in status.values():
            if res['stat']['exists']:
                copied_1.append(True)
    if copied_1[0]:
        log.info("Installing External CA")
        output = ansible_module.command('pkispawn -s CA -f /root/{}'.format(step1_cfg))
        for res in output.values():
            if res['rc'] == 0:
                assert "A CSR for the CA signing certificate has been generated in:" in res['stdout']
                partial_install = True
                log.info("A CSR for the CA signing certificate has been generated in: "
                         "/root/ca_signing.csr")
            else:
                log.error("Failed to install External CA step1.")
                pytest.xfail()
    if partial_install:
        log.info("Submitting the certificate request.")
        submit_req = ansible_module.pki(cli='ca-cert-request-submit',
                                        port=constants.CA_HTTP_PORT,
                                        dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                        nssdb=temp_dir,
                                        certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                        extra_args='--profile caCACert --csr-file '
                                                   '/root/ca_signing.csr')

        for result in submit_req.values():
            if result['rc'] == 0:
                request_id = re.findall(r'Request ID: [\w].*', result['stdout'])[0]
                request_id = request_id.split(":")[1].strip()
            else:
                log.error("Failed to submit certificate request for ExternalCA.")
                pytest.xfail()
            approve_req = ansible_module.pki(cli='ca-cert-request-review',
                                             port=constants.CA_HTTP_PORT,
                                             nssdb=temp_dir,
                                             dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                             certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                             extra_args='--action approve {}'.format(request_id))

            for result in approve_req.values():
                if result['rc'] == 0:
                    cert_id = re.findall(r'Certificate ID: [\w]*', result['stdout'])[0]
                    cert_id = cert_id.split(":")[1].strip()
                    log.info("Approved the certificate request, Cert ID: {}".format(cert_id))
                else:
                    log.error("Failed to Approve the certificate request of ExternalCA.")
                    pytest.xfail()

            if cert_id:
                # Exporting ca cert chain.
                certutil_cmd = 'certutil -L -d {} -n "CA Signing Certificate - topology-{}_Foobarmaster.org" -a -o /root/cert_chain.p7b'
                certutil_out = ansible_module.command(certutil_cmd.format(temp_dir, topology))
                for res3 in certutil_out.values():
                    assert res3['rc'] == 0
                    log.info("Exported cert chain to : /root/cert_chain.p7b")

                get_server_cert = ansible_module.pki(
                    cli='ca-cert-show',
                    port=constants.CA_HTTP_PORT,
                    nssdb=temp_dir,
                    dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                    certnick="'{}'".format(constants.CA_ADMIN_NICK),
                    extra_args='--output /root/ca_signing.crt {}'.format(cert_id))

                for res2 in get_server_cert.values():
                    if res2['rc'] == 0:
                        assert 'Serial Number: {}'.format(cert_id) in res2['stdout']
                        log.info("Stored the approved certificate request in /root/ca_signing.crt")
                    else:
                        log.error("Failed to store certificate request in /root/ca_signing.crt")
                        pytest.xfail()
    install = ansible_module.command('pkispawn -s CA -f /root/{}'.format(step2_cfg))

    for res in install.values():
        log.info("Running : {}".format(res['cmd']))
        assert res['rc'] == 0
        log.info("Installation Successful.")

    yield

    uninstall = ansible_module.command('pkidestroy -s CA -i ExternalCA')
    for res in uninstall.values():
        log.info("Running: {}".format(res['cmd']))
        if res['rc'] == 0:
            assert 'Uninstallation complete.' in res['stdout']
            log.info("Uninstallation complete.")
        else:
            log.error("Failed to uninstall ExternalCA")
            log.info(res['stderr'])
            pytest.xfail()
    for f in [step1_cfg, step2_cfg, 'ca_signing.crt', 'cert_chain.p7b', 'ca_signing.csr']:
        rm_cmd = "rm -rf /root/{}".format(f)
        log.info("Removing: {}".format(rm_cmd))
        ansible_module.command(rm_cmd)
    log.info("Removing: {}".format(temp_dir))
    shutil.rmtree(temp_dir)


def test_bug_1499054_ca_cert_withot_ski_causes_issuance_failure(ansible_module, setup_ca):
    """
    :id: 4f96c511-644e-4ad8-ab83-fa56519cc354

    :Title: RHCS-TC Test CA Certificate without SKI causes external CA installation
            failure. BZ: 1499054

    :Test: Test CA certificate without SKI causes external CA installation failure.BZ 1499054

    :Description:
        If SKI extension is missing from the CA certificate then external CA installation
        was failing.

    :Requirement: RHCS-REQ Certificate Authority Installation and Deployment

    :CaseComponent: \-

    :Setup:
        To setup CA with external CA signing certificate follow the following steps:
            1. Create ca-external-step1.cfg file.
                [DEFAULT]
                pki_token_password = Secret123
                pki_admin_password = Secret123
                pki_hostname = pki1.example.com
                pki_security_domain_name = topology-02_Foobarmaster.org
                pki_security_domain_password = Secret123
                pki_client_dir = /opt/pki-tomcat
                pki_client_pkcs12_password = Secret123
                pki_backup_keys = True
                pki_backup_password = Secret123
                pki_ds_password = Secret123
                pki_ds_ldap_port = 389
                pki_ssl_server_key_algorithm=SHA512withRSA
                pki_ssl_server_key_size=2048
                pki_ssl_server_key_type=rsa
                pki_subsystem_key_algorithm=SHA512withRSA
                pki_subsystem_key_size=2048
                pki_subsystem_key_type=rsa
                [CA]
                pki_admin_email=caadmin@example.com
                pki_admin_name=caadmin
                pki_admin_nickname=caadmin
                pki_admin_password=Secret.123
                pki_admin_uid=caadmin

                pki_backup_keys=True
                pki_backup_password=Secret.123

                pki_client_database_password=Secret.123
                pki_client_database_purge=False
                pki_client_pkcs12_password=Secret.123

                pki_ds_base_dn=dc=ca,dc=example,dc=com
                pki_ds_database=ca
                pki_ds_password=Secret.123

                pki_security_domain_name=EXAMPLE
                pki_token_password=Secret.123

                pki_external=True
                pki_external_step_two=False

                # PKI 10.5 or newer
                pki_ca_signing_csr_path=ca_signing.csr

                # PKI 10.4 or older
                pki_external_csr_path=ca_signing.csr

            2. Create ca-external-step2.cfg file
                [DEFAULT]
                pki_token_password = Secret123
                pki_admin_password = Secret123
                pki_hostname = pki1.example.com
                pki_security_domain_name = topology-02_Foobarmaster.org
                pki_security_domain_password = Secret123
                pki_client_dir = /opt/pki-tomcat
                pki_client_pkcs12_password = Secret123
                pki_backup_keys = True
                pki_backup_password = Secret123
                pki_ds_password = Secret123
                pki_ds_ldap_port = 389
                pki_ssl_server_key_algorithm=SHA512withRSA
                pki_ssl_server_key_size=2048
                pki_ssl_server_key_type=rsa
                pki_subsystem_key_algorithm=SHA512withRSA
                pki_subsystem_key_size=2048
                pki_subsystem_key_type=rsa
                [CA]
                pki_admin_email=caadmin@example.com
                pki_admin_name=caadmin
                pki_admin_nickname=caadmin
                pki_admin_password=Secret.123
                pki_admin_uid=caadmin

                pki_backup_keys=True
                pki_backup_password=Secret.123

                pki_client_database_password=Secret.123
                pki_client_database_purge=False
                pki_client_pkcs12_password=Secret.123

                pki_ds_base_dn=dc=ca,dc=example,dc=com
                pki_ds_database=ca
                pki_ds_password=Secret.123

                pki_security_domain_name=EXAMPLE
                pki_token_password=Secret.123

                pki_external=True
                pki_external_step_two=True

                pki_external_step_two=True
                pki_ca_signing_cert_path=ca_signing.crt

                pki_cert_chain_nickname=Root CA Signing Certificate

                pki_cert_chain_path=cert_chain.p7b

    :Steps:
            1. Run the ca-external-step1.cfg using pkispawn, it will generate the ca_signing.crt.
            2. Submit the certificate request to the another CA, Sign the certificate from the CA.
            3. Copy the certificate and CA certificate or Certificate with Chain, store it
               in 'cert_chain.p7b' file.
            4. Run ca-external-step2.cfg using pkispawn.
            5. Go to the /var/lib/pki/<instance>/alias dir.
            6. Pretty Print the caSigningCert.
            7. Check that caSigningCert should have 'Subject Key Identifier' Extension.

    :Expectedresults:
                1. Dual step external certificate installation should be successful.
                2. caSigningCert should have 'Subject Key Identifier' extension.
    """
    signing_cert_name = 'caSigningCert cert-ExternalCA CA'
    alias_dir = '/var/lib/pki/ExternalCA/alias'

    certutil_out = ansible_module.command('certutil -L -d {} -n "{}"'.format(alias_dir,
                                                                             signing_cert_name))
    for res in certutil_out.values():
        log.info("Running : {}".format(res['cmd']))
        if res['rc'] == 0:
            assert 'Name: Certificate Subject Key ID' in res['stdout']
            log.info("Subject Key ID found.")
        else:
            log.error("Failed to check Subject Key ID in the certificate.")
            log.info(res['stderr'])
            pytest.xfail()
