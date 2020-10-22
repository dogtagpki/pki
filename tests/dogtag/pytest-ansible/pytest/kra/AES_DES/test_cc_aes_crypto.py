"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Verify CC AES Crypto Features
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Deepak Punia
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2018 Red Hat, Inc. All rights reserved.
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
import time
import os
import random
import re
import logging
import sys
import datetime
import pytest
import requests
from pki.testlib.common.certlib import CertSetup
try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

HOST = constants.MASTER_HOSTNAME

CA_INFO_SERVICE = ["<ArchivalMechanism>keywrap</ArchivalMechanism>"]

KRA_INFO_SERVICE = ["<ArchivalMechanism>keywrap</ArchivalMechanism>",
                    "<EncryptAlgorithm>AES/CBC/PKCS5Padding</EncryptAlgorithm>",
                    "<RecoveryMechanism>keywrap</RecoveryMechanism>",
                    "<WrapAlgorithm>AES KeyWrap/Padding</WrapAlgorithm>"]

kra_allow_in_cfg = '''kra.allowEncDecrypt.archival=true
kra.allowEncDecrypt.recovery=true
kra.legacyPKCS12=false'''

kra_cfg = "/var/lib/pki/{}/kra/conf/CS.cfg".format(constants.KRA_INSTANCE_NAME)
srcpyclient = "{}/pytest/kra/AES_DES/pki_python_client_rest_api.py".format(os.environ["PYTEST_DIR"])
destpyclient = "/tmp/pki_python_client_rest_api.py"

pkiconf = "/usr/share/pki/etc/pki.conf"
CS_CFG_FILE = '/var/lib/pki/{}/{}/conf/CS.cfg'

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout)

date = str(datetime.date.today())

@pytest.mark.setup
def test_setup(ansible_module):
    """
    Prerequisites for running pytest-ansible tests
    """
    cert_setup = CertSetup(nssdb=constants.NSSDB,
                           db_pass=constants.CLIENT_DATABASE_PASSWORD,
                           host='pki1.example.com',
                           port=constants.CA_HTTP_PORT,
                           nick="'{}'".format(constants.CA_ADMIN_NICK))
    try:
        cert_setup.create_certdb(ansible_module)
        cert_setup.import_ca_cert(ansible_module)
        cert_setup.import_admin_p12(ansible_module, 'ca')
    except Exception as e:
        print(e)

    cert_setup.import_admin_p12(ansible_module, 'kra')

def test_pki_kra_aes_crypto_exits_in_cs_cfg_params(ansible_module):
    """
    :Title: Test additional params added for AES Crypto

    :Description: Test additional params added for AES Crypto

    :Setup:
        1. Setup DS instance
        2. CA,KRA Subsystems should point to the LDAPS port

    :Steps:
        1. Check if newly added params exist in CS.cfg
           kra.storageUnit.wrapping.0.sessionKeyLength
           kra.storageUnit.wrapping.0.sessionKeyWrapAlgorithm=RSA
           kra.storageUnit.wrapping.0.payloadEncryptionPadding=PKCS5Padding
           kra.storageUnit.wrapping.0.sessionKeyKeyGenAlgorithm=DES3
           kra.storageUnit.wrapping.0.payloadEncryptionAlgorithm=DES3
           kra.storageUnit.wrapping.0.payloadEncryptionMode=CBC
           kra.storageUnit.wrapping.0.payloadWrapAlgorithm=DES3/CBC/PAD
           kra.storageUnit.wrapping.0.sessionKeyType=DES3
           kra.storageUnit.wrapping.0.sessionKeyLength=256
           kra.storageUnit.wrapping.1.sessionKeyWrapAlgorithm=RSA
           kra.storageUnit.wrapping.1.payloadEncryptionPadding=PKCS5Padding
           kra.storageUnit.wrapping.1.sessionKeyKeyGenAlgorithm=AES
           kra.storageUnit.wrapping.1.payloadEncryptionAlgorithm=AES
           kra.storageUnit.wrapping.1.payloadEncryptionMode=CBC
           kra.storageUnit.wrapping.1.payloadWrapAlgorithm=AES KeyWrap/Padding
           kra.storageUnit.wrapping.1.sessionKeyType=AES
           kra.storageUnit.wrapping.choice=1

    :Expectedresults:
        1. DS instance should be successfully setup with SSL
        2. Subsystems should be able to communication with LDAPS
        3. Verify whether newly added params exist in CS.cfg mention in step 1
    """
    CS_cfg_content = ansible_module.command("cat {}".format(CS_CFG_FILE.format(constants.KRA_INSTANCE_NAME, 'kra')))
    for result in CS_cfg_content.values():
        if result['rc'] == 0:
            assert "kra.storageUnit.wrapping.0.sessionKeyLength" in result['stdout']
            assert "kra.storageUnit.wrapping.0.sessionKeyWrapAlgorithm=RSA" in result['stdout']
            assert "kra.storageUnit.wrapping.0.payloadEncryptionPadding=PKCS5Padding" in result['stdout']
            assert "kra.storageUnit.wrapping.0.sessionKeyKeyGenAlgorithm=DESede" in result['stdout']
            assert "kra.storageUnit.wrapping.0.payloadEncryptionAlgorithm=DESede" in result['stdout']
            assert "kra.storageUnit.wrapping.0.payloadEncryptionMode=CBC" in result['stdout']
            assert "kra.storageUnit.wrapping.0.payloadWrapAlgorithm=DES3/CBC/Pad" in result['stdout']
            assert "kra.storageUnit.wrapping.0.sessionKeyType=DESede" in result['stdout']
            assert "kra.storageUnit.wrapping.1.sessionKeyWrapAlgorithm=RSA" in result['stdout']
            assert "kra.storageUnit.wrapping.1.payloadEncryptionPadding=PKCS5Padding" in result['stdout']
            assert "kra.storageUnit.wrapping.1.sessionKeyKeyGenAlgorithm=AES" in result['stdout']
            assert "kra.storageUnit.wrapping.1.payloadEncryptionAlgorithm=AES" in result['stdout']
            assert "kra.storageUnit.wrapping.1.payloadEncryptionMode=CBC" in result['stdout']
            assert "kra.storageUnit.wrapping.1.payloadWrapAlgorithm=AES KeyWrap/Padding" in result['stdout']
            assert "kra.storageUnit.wrapping.1.sessionKeyType=AES" in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            pytest.fail()


def test_pki_kra_check_wrapping_choice_in_cs_cfg(ansible_module):
    """
    :Title: Test to check if kra.storageUnit.wrapping.choice is set to 1

    :Description: Test to check if kra.storageUnit.wrapping.choice is set to 1

    :Steps:
        1. Check if  kra.storageUnit.wrapping.choice is set to 1 in CS.cfg file

    :Expectedresults:
        1. Verify if kra.storageUnit.wrapping.choice is set to 1
    """
    CS_cfg_content = ansible_module.command("cat {}".format(CS_CFG_FILE.format(constants.KRA_INSTANCE_NAME, 'kra')))
    for result in CS_cfg_content.values():
        if result['rc'] == 0:
            assert "kra.storageUnit.wrapping.choice=1" in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            pytest.fail()


def test_pki_kra_metainfo_for_encrypted_keys_in_kra_db(ansible_module):
    """
    :Title: Test to check if metaInfo entries are present in logs when keys are encrypted and stored in KRA DB

    :Description: Test to check if metaInfo entries are present in logs when keys are encrypted and stored in KRA DB
    :Steps:
        1. Archive a key
        2. Check if metaInfo entries are present in logs when keys are encrypted and stored in KRA DB
           dn: cn=41,ou=keyRepository,ou=kra,o=pki-tomcat-KRA
           objectClass: top
           objectClass: keyRecord
           keyState: VALID
           serialno: 0241
           ...
           metaInfo: sessionKeyLength:256
           metaInfo: sessionKeyWrapAlgorithm:RSA
           metaInfo: payloadEncryptionPadding:PKCS5Padding
           metaInfo: sessionKeyKeyGenAlgorithm:AES
           metaInfo: payloadEncryptionAlgorithm:AES
           metaInfo: payloadEncryptionIV:AQEBAQEBAQEBAQEBAQEBAQ==
           metaInfo: payloadEncryptionMode:CBC
           metaInfo: payloadWrapAlgorithm:AES KeyWrap/Padding
           metaInfo: sessionKeyType:AES

    :Expectedresults:
        1. key-archival should be successful
        2. metaInfo entries should be present in KRA DB when keys are archived and stored as mentioned in step 3
    """
    # archive key
    clientKeyID = 'test_key{}'.format(random.randint(1111, 99999999))
    archive_passphrase = ansible_module.pki(cli='kra-key-archive',
                                            nssdb=constants.NSSDB,
                                            dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                            port=constants.KRA_HTTPS_PORT,
                                            hostname=constants.MASTER_HOSTNAME,
                                            protocol='https',
                                            certnick="'{}'".format(constants.KRA_ADMIN_NICK),
                                            extra_args="--clientKeyID {} --passphrase {}".format(clientKeyID,
                                                                                                 constants.CLIENT_DATABASE_PASSWORD))
    for result in archive_passphrase.values():
        if result['rc'] == 0:
            kra_key_request_id = re.findall('Key ID:.*', result['stdout'])
            kra_key_searial_id = int(kra_key_request_id[0].split(":")[1].strip(), 16)
            assert "Archival request details" in result['stdout']
            assert "Request ID:" in result['stdout']
            assert "Key ID:" in result['stdout']
            assert "Type: securityDataEnrollment" in result['stdout']
            assert "Status: complete" in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            pytest.fail()
    # search ldap entry with kra request id
    ldap_entry = ansible_module.command("ldapsearch -x -D '{}' -h {} -p {} -w {} "
                                        "-b 'cn={},ou=keyRepository,ou=kra,o={}-KRA'".format(constants.LDAP_BIND_DN,
                                                                                             constants.MASTER_HOSTNAME,
                                                                                             constants.LDAP_PORT,
                                                                                             constants.LDAP_PASSWD,
                                                                                             kra_key_searial_id,
                                                                                             constants.KRA_INSTANCE_NAME))
    for result in ldap_entry.values():
        if result['rc'] == 0:
            assert "keyState: VALID" in result['stdout']
            assert "ownerName: kraadmin" in result['stdout']
            assert "metaInfo: sessionKeyWrapAlgorithm:RSA" in result['stdout']
            assert "metaInfo: payloadEncrypted:true" in result['stdout']
            assert "metaInfo: sessionKeyKeyGenAlgorithm:AES" in result['stdout']
            assert "metaInfo: sessionKeyType:AES" in result['stdout']
            assert "metaInfo: sessionKeyLength:128" in result['stdout']
            assert "metaInfo: payloadEncryptionOID:2.16.840.1.101.3.4.1.2" in result['stdout']
            assert "archivedBy: kraadmin" in result['stdout']
            assert "clientId: {}".format(clientKeyID) in result['stdout']
            assert "status: active" in result['stdout']
            assert "dataType: passPhrase" in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            pytest.fail()
    # test with generating the the kra key
    clientKeyID = 'test_key{}'.format(random.randint(1111, 99999999))
    archive_keys = ansible_module.pki(cli='kra-key-generate',
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.KRA_HTTPS_PORT,
                                      hostname=constants.MASTER_HOSTNAME,
                                      protocol='https',
                                      certnick="'{}'".format(constants.KRA_ADMIN_NICK),
                                      extra_args="{} --key-algorithm AES "
                                                 "--key-size 128 "
                                                 "--usages wrap".format(clientKeyID))
    for result in archive_keys.values():
        if result['rc'] == 0:
            kra_key_request_id = re.findall('Key ID:.*', result['stdout'])
            kra_key_searial_id = int(kra_key_request_id[0].split(":")[1].strip(), 16)
            assert "Key generation request info" in result['stdout']
            assert "Request ID:" in result['stdout']
            assert "Key ID:" in result['stdout']
            assert "Type: symkeyGenRequest" in result['stdout']
            assert "Status: complete" in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            pytest.fail()
    # search entry for generated kra key
    ldap_entry = ansible_module.command("ldapsearch -x -D '{}' -h {} -p {} -w {} \
                                            -b 'cn={},ou=keyRepository,ou=kra,o={}-KRA'".format(constants.LDAP_BIND_DN,
                                                                                                HOST,
                                                                                                constants.LDAP_PORT,
                                                                                                constants.LDAP_PASSWD,
                                                                                                kra_key_searial_id,
                                                                                                constants.KRA_INSTANCE_NAME))
    for result in ldap_entry.values():
        if result['rc'] == 0:
            assert "keyState: VALID" in result['stdout']
            assert "ownerName: kraadmin" in result['stdout']
            assert "keySize: 128" in result['stdout']
            assert "algorithm: AES" in result['stdout']
            assert "metaInfo: sessionKeyWrapAlgorithm:RSA" in result['stdout']
            assert "metaInfo: payloadEncrypted:" in result['stdout']
            assert "metaInfo: sessionKeyKeyGenAlgorithm:AES" in result['stdout']
            assert "metaInfo: sessionKeyType:AES" in result['stdout']
            assert "metaInfo: sessionKeyLength:128" in result['stdout']
            assert "metaInfo: payloadEncryptionOID:2.16.840.1.101.3.4.1.2" in result['stdout']
            assert "archivedBy: kraadmin" in result['stdout']
            assert "clientId: {}".format(clientKeyID) in result['stdout']
            assert "status: active" in result['stdout']
            assert "dataType:" in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            pytest.fail()


@pytest.mark.parametrize('port', (constants.KRA_HTTP_PORT, constants.KRA_HTTPS_PORT))
def test_kra_browser_info_service_through_url(ansible_module, port):
    """
    :Title: Test KRA Info Service

    :Description: Test KRA Info Service

    :Steps:
        3. Access the KRAInfoService at /kra/rest/info URL
        4. The info service should return XML mentioned in attachment 1

    :Expectedresults:
        3. KRAInfoService should be accessible at /kra/rest/info URL
        4. The info service should return XML mentioned in attachment 1
    """
    ansible_module.fetch(src=constants.ROOT_CA_CERT_PATH, dest=constants.ROOT_CA_CERT_PATH, flat=True)
    # check the kra http and https url /kra/rest/info
    if port == constants.KRA_HTTP_PORT:
        response = requests.get('http://{}:{}/kra/rest/info'.format(HOST, port))
        assert response.status_code == 200
        for info_service in KRA_INFO_SERVICE:
            try:
                assert info_service in response.text
                log.info("Log service: {} found".format(info_service))
            except Exception as e:
                log.error(e)
                log.error("Service : {} not found".format(info_service))

    elif port == constants.KRA_HTTPS_PORT:
        response = requests.get('https://{}:{}/kra/rest/info'.format(HOST, port), verify=constants.ROOT_CA_CERT_PATH)
        assert response.status_code == 200
        for info_service in KRA_INFO_SERVICE:
            try:
                assert info_service in response.text
                log.info("Log service: {} found".format(info_service))
            except Exception as e:
                log.error(e)
                log.error("Service : {} not found".format(info_service))


@pytest.mark.parametrize('port', (constants.CA_HTTP_PORT, constants.CA_HTTPS_PORT))
def test_ca_browser_info_service_through_url(ansible_module, port):
    """
    :Title: Test CA Info Service

    :Description: Test CA Info Service
    :Steps:
        1. Access CAInfoService at ca/rest/info URL
        2. The info service should return XML mentioned in attachment 2

    :Expectedresults:
        3. CAInfoService should be accessible at ca/rest/info
        4. The info service should return the XML mentioned in attachment 2
    """
    # check the ca http and https url /ca/rest/info
    if port == constants.CA_HTTP_PORT:
        response = requests.get('http://{}:{}/ca/rest/info'.format(HOST, port))
        assert response.status_code == 200
        for info_service in CA_INFO_SERVICE:
            try:
                assert info_service in response.text
                log.info("Log service: {} found".format(info_service))
            except Exception as e:
                log.error(e)
                log.error("Service : {} not found".format(info_service))
    elif port == constants.CA_HTTPS_PORT:
        response = requests.get('https://{}:{}/ca/rest/info'.format(HOST, port), verify=constants.ROOT_CA_CERT_PATH)
        assert response.status_code == 200
        for info_service in CA_INFO_SERVICE:
            try:
                assert info_service in response.text
                log.info("Log service: {} found".format(info_service))
            except Exception as e:
                log.error(e)
                log.error("Service : {} not found".format(info_service))


def test_aes_algorithm_using_pki_python_client(ansible_module):
    """
    :Title: Test python client uses AES

    :Description: Test python client uses AES

    :Steps:
        3. Check if python client uses AES
        4. Check logs if algorithm used for encryption is AES when python client is used

    :Expectedresults:
        3. python client should use AES algorithm
        4. Logs should show that AES is used when python client is used
    """
    # adding allow enc/dec configuration in kra CS.cfg file
    ansible_module.lineinfile(dest=kra_cfg, line=kra_allow_in_cfg, state="present")
    ansible_module.lineinfile(path=kra_cfg, regexp='debug.level=10', line='debug.level=0')
    for i in [constants.CA_INSTANCE_NAME, constants.KRA_INSTANCE_NAME]:
        subsystem = 'systemctl restart pki-tomcatd@{}'.format(i)
        ansible_module.command(subsystem)
        log.info("Restarted {} instance.".format(i))
        time.sleep(10)

    # generating certificate used by python client api
    convrt_p12_cmd = ansible_module.shell("openssl pkcs12 -in {}/kra_admin_cert.p12 "
                                          "-out /tmp/admin_cert.pem -nodes -passin pass:{}".format
                                          (constants.KRA_CLIENT_DIR,
                                           constants.CLIENT_DATABASE_PASSWORD))
    for result in convrt_p12_cmd.values():
        if result['rc'] == 0:
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            pytest.fail()

    ansible_module.copy(src=srcpyclient, dest=destpyclient)
    # running python client py script and destination server
    pycli_aes_test = ansible_module.shell("python {}".format(destpyclient))
    for result in pycli_aes_test.values():
        if result['rc'] == 0:
            assert "Key_id=" in result['stdout']
            assert "pki.key.KeyInfo object at" in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            pytest.fail()
    log_cmd = "tail -n 700 /var/log/pki/{}/kra/debug.{}.log".format(constants.KRA_INSTANCE_NAME, date)
    log_result = ansible_module.command(log_cmd)
    for result in log_result.values():
        if result['rc'] == 0:
            assert "SymKeyGenService: algorithm: AES" in result['stdout']
            assert "StorageKeyUnit.wrap interal" in result['stdout']
            assert "StorageKeyUnit:wrap() privKey wrapped" in result['stdout']
            assert "StorageKeyUnit:wrap() session key wrapped" in result['stdout']
            assert "SYMKEY_GENERATION_REQUEST_PROCESSED" in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            pytest.fail()


def test_des3_algorithm_using_pki_python_client(ansible_module):
    """
    :Title: Test client uses DES3 for communication

    :Description: Test client uses DES3 for communication

    :Steps:
        3. client should use 3DES for communication
        4. Logs should show that 3DES is used for client communication

    :Expectedresults:
        3. client should use 3DES for communication
        4. Logs should show that 3DES is used for client communication
    """
    # DES3 algorithm with 168 key size
    ansible_module.copy(src=srcpyclient, dest=destpyclient)
    ansible_module.replace(path=destpyclient, regexp="AES", replace="DES3")
    ansible_module.replace(path=pkiconf, regexp='KEY_WRAP_PARAMETER_SET=1',
                           replace='KEY_WRAP_PARAMETER_SET=0')
    ansible_module.replace(path=destpyclient,
                           regexp="key_size = 128",
                           replace="key_size = 168")

    for i in [constants.CA_INSTANCE_NAME, constants.KRA_INSTANCE_NAME]:
        subsystem = 'systemctl restart pki-tomcatd@{}'.format(i)
        ansible_module.command(subsystem)
        log.info("Restarted {} instance.".format(i))
        time.sleep(10)

    pycli_aes_test = ansible_module.shell("python {}".format(destpyclient))
    for result in pycli_aes_test.values():
        if result['rc'] == 0:
            assert "keyset=0" in result['stdout']
            assert "Key_id=" in result['stdout']
            assert "pki.key.KeyInfo object at" in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            pytest.fail()
    # checking the last generated debug log
    log_cmd = "tail -n 700 /var/log/pki/{}/kra/debug.{}.log".format(constants.KRA_INSTANCE_NAME, date)
    log_result = ansible_module.command(log_cmd)
    for result in log_result.values():
        if result['rc'] == 0:
            assert "SymKeyGenService: algorithm: DES3" in result['stdout']
            assert "StorageKeyUnit.wrap interal" in result['stdout']
            assert "StorageKeyUnit:wrap() privKey wrapped" in result['stdout']
            assert "StorageKeyUnit:wrap() session key wrapped" in result['stdout']
            assert "SYMKEY_GENERATION_REQUEST_PROCESSED" in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            pytest.fail()


def test_pki_python_client_supports_aes_key_wrap_algorithm(ansible_module):
    """
    :Title: Test post 10.4 client supports AES Key Wrap

    :Description: Test post 10.4 client supports AES Key Wrap

    :Steps:
        3. client should support AES Key Wrap

    :Expectedresults:
        3. client should support AES Key Wrap
    """
    # enabling key wraping paratmer in pki.conf file
    ansible_module.replace(path=pkiconf, regexp='KEY_WRAP_PARAMETER_SET=0',
                           replace='KEY_WRAP_PARAMETER_SET=1')

    for i in [constants.CA_INSTANCE_NAME, constants.KRA_INSTANCE_NAME]:
        subsystem = 'systemctl restart pki-tomcatd@{}'.format(i)
        ansible_module.command(subsystem)
        log.info("Restarted {} instance.".format(i))
        time.sleep(10)

    ansible_module.copy(src=srcpyclient, dest=destpyclient)

    pycli_aes_test = ansible_module.shell("python {}".format(destpyclient))
    for result in pycli_aes_test.values():
        if result['rc'] == 0:
            assert "Key_id=" in result['stdout']
            assert "pki.key.KeyInfo object at" in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            pytest.fail()

    log_cmd = "tail -n 700 /var/log/pki/{}/kra/debug.{}.log".format(constants.KRA_INSTANCE_NAME, date)
    log_result = ansible_module.command(log_cmd)
    for result in log_result.values():
        if result['rc'] == 0:
            assert "SymKeyGenService: algorithm: AES" in result['stdout']
            assert "StorageKeyUnit.wrap interal" in result['stdout']
            assert "StorageKeyUnit:wrap() privKey wrapped" in result['stdout']
            assert "StorageKeyUnit:wrap() session key wrapped" in result['stdout']
            assert "SYMKEY_GENERATION_REQUEST_PROCESSED" in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            pytest.fail()


def test_pki_python_client_uses_key_wrap_usage(ansible_module):
    """
    :Title: Test post 10.4 client uses Key Wrapping but uses AES/128/CBC

    :Description: Test client uses Key Wrapping but uses AES/128/CBC
    :Steps:
        3. uses key wrapping but uses AES/128/CBC

    :Expectedresults:
        3. uses key wrapping but uses AES/128/CBC
    """
    ansible_module.copy(src=srcpyclient, dest=destpyclient)

    ansible_module.replace(path=destpyclient,
                           regexp="DECRYPT_USAGE",
                           replace="WRAP_USAGE")
    ansible_module.replace(path=pkiconf, regexp='KEY_WRAP_PARAMETER_SET=0',
                           replace='KEY_WRAP_PARAMETER_SET=1')

    for i in [constants.CA_INSTANCE_NAME, constants.KRA_INSTANCE_NAME]:
        subsystem = 'systemctl restart pki-tomcatd@{}'.format(i)
        ansible_module.command(subsystem)
        log.info("Restarted {} instance.".format(i))
        time.sleep(10)

    pycli_aes_test = ansible_module.shell("python {}".format(destpyclient))
    for result in pycli_aes_test.values():
        if result['rc'] == 0:
            assert "keyset=1" in result['stdout']
            assert "Key_id=" in result['stdout']
            assert "pki.key.KeyInfo object at" in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            pytest.fail()
    log_cmd = "tail -n 700 /var/log/pki/{}/kra/debug.{}.log".format(constants.KRA_INSTANCE_NAME, date)
    log_result = ansible_module.command(log_cmd)
    for result in log_result.values():
        if result['rc'] == 0:
            assert "SymKeyGenService: algorithm: AES" in result['stdout']
            assert "SymKeyGenService: request ID:" in result['stdout']
            assert "StorageKeyUnit:wrap() privKey wrapped" in result['stdout']
            assert "StorageKeyUnit:wrap() session key wrapped" in result['stdout']
            assert "SYMKEY_GENERATION_REQUEST_PROCESSED" in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            pytest.fail()


def test_pki_python_client_keyset_check(ansible_module):
    """
    :id: c5c386ff-3d83-4e38-914f-d44f53dda045

    :Title:Test python client keyset check

    :Description: Test python client keyset check

    :Steps:
        3. Check keyset value to determine secret encryption algorithm
           for example:
           keyset = 0, 3DES-CBC with PKCS 1.5 padding
           keyset =1, AES 128 bit CBC with PKCS 1.5 padding
        4. The secret encryption algorithm should be selected based on the keyset value

    :Expectedresults:
        3. Keyset value will determine the secret encryption algorithm
        4. The secret encryption algorithm should be selected based on the keyset value
    """
    ansible_module.copy(src=srcpyclient, dest=destpyclient)
    ansible_module.replace(path=pkiconf, regexp='KEY_WRAP_PARAMETER_SET=0',
                           replace='KEY_WRAP_PARAMETER_SET=1')

    for i in [constants.CA_INSTANCE_NAME, constants.KRA_INSTANCE_NAME]:
        subsystem = 'systemctl restart pki-tomcatd@{}'.format(i)
        ansible_module.command(subsystem)
        log.info("Restarted {} instance.".format(i))
        time.sleep(10)

    pycli_aes_test = ansible_module.shell("python {}".format(destpyclient))
    for result in pycli_aes_test.values():
        if result['rc'] == 0:
            assert "keyset=1" in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            pytest.fail()

    ansible_module.replace(path=pkiconf, regexp='KEY_WRAP_PARAMETER_SET=1',
                           replace='KEY_WRAP_PARAMETER_SET=0')

    for i in [constants.CA_INSTANCE_NAME, constants.KRA_INSTANCE_NAME]:
        subsystem = 'systemctl restart pki-tomcatd@{}'.format(i)
        ansible_module.command(subsystem)
        log.info("Restarted {} instance.".format(i))
        time.sleep(10)

    pycli_aes_test = ansible_module.shell("python {}".format(destpyclient))
    for result in pycli_aes_test.values():
        if result['rc'] == 0:
            assert "keyset=0" in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            pytest.fail()


def test_key_retrieval_for_encryption_using_pki_python_client(ansible_module):
    """
    :Title:Test retrieval for encryption

    :Description: Test retrieval for encryption
    Steps:
        1> Use the python client and request key
        2> retrieve the key using python client
        3> check the logs should show key retrieve
    :Expectedresults:
        1. Key should archive successfully.
        2. Log should show success message.
    """
    retrieve_key = "key_data = keyclient.retrieve_key(key_info.get_key_id()," \
                   "trans_wrapped_session_key=wrapped_session_key)"
    ansible_module.copy(src=srcpyclient, dest=destpyclient)
    ansible_module.lineinfile(dest=destpyclient, line=retrieve_key)
    pycli_aes_test = ansible_module.shell("python {}".format(destpyclient))
    for result in pycli_aes_test.values():
        if result['rc'] == 0:
            assert "Key_id=" in result['stdout']
            assert "pki.key.KeyInfo object at" in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            pytest.fail()

    log_cmd = "tail -n 700 /var/log/pki/{}/kra/debug.{}.log".format(constants.KRA_INSTANCE_NAME, date)
    log_result = ansible_module.command(log_cmd)
    for result in log_result.values():
        if result['rc'] == 0:
            assert "KeyResource.retrieveKey" in result['stdout']
            assert "master connection is connected: true" in result['stdout']
            assert "SECURITY_DATA_RECOVERY_REQUEST_PROCESSED" in result['stdout']
            assert "SECURITY_DATA_EXPORT_KEY" in result['stdout']
            assert "SYMKEY_GENERATION_REQUEST_PROCESSED" in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            pytest.fail()
