#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   Description:
#   Bug 1489256 - [RFE] jss should support RSA with OAEP padding
#   Bug 1883656 - [RFE] Add OAEP as a KeyWrap algorithm for KRA in Dogtag PKI
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   Author: Pritam Singh <prisingh@redhat.com>
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Copyright Red Hat, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""
import logging
import os
import re
import time
import sys
import tempfile
import datetime

import pytest

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

TOPOLOGY = int(constants.CA_INSTANCE_NAME.split("-")[-2])
log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
date = datetime.datetime.now().strftime("%Y-%m-%d")
BASE_DIR = '/var/lib/pki/'
ca_cfg_path = BASE_DIR + '/' + '{}'.format(constants.CA_INSTANCE_NAME) + '/' + 'ca/conf/CS.cfg'
kra_cfg_path = BASE_DIR + '/' + '{}'.format(constants.KRA_INSTANCE_NAME) + '/' + 'kra/conf/CS.cfg'


@pytest.fixture()
def setup_fixture(ansible_module):
    ansible_module.command('cp -r /tmp/test_dir/ /tmp/test_conf/')

    log.info("Creating ldap instance.")
    ldap_setup = ansible_module.command('dscreate from-file /tmp/test_conf/ldap.cfg')
    for r in ldap_setup.values():
        assert r['rc'] == 0
        log.info("Created ldap instance.")

    log.info("Creating CA instance.")
    ca_setup = ansible_module.command('pkispawn -s CA -f /tmp/test_conf/ca.cfg')
    for r in ca_setup.values():
        assert r['rc'] == 0
        log.info("Created CA instance.")
    ansible_module.copy(src='/var/lib/pki/{}/alias/ca.crt'.format(constants.CA_INSTANCE_NAME), dest='/tmp/rootCA.pem', remote_src='yes' )
    log.info("Creating KRA instance.")
    kra_setup = ansible_module.command('pkispawn -s KRA -f /tmp/test_conf/kra.cfg')
    for r in kra_setup.values():
        assert r['rc'] == 0
        log.info("Created KRA instance.")

    yield

    # teardown
    log.info("Removing KRA instance.")
    res = ansible_module.command('pkidestroy -s KRA -i {}'.format(constants.KRA_INSTANCE_NAME))
    for r in res.values():
        assert r['rc'] == 0
        log.info("Removed KRA instance.")

    log.info("Removing CA instance.")
    res = ansible_module.command('pkidestroy -s CA -i {}'.format(constants.CA_INSTANCE_NAME))
    for r in res.values():
        assert r['rc'] == 0
        log.info("Removed CA instance.")

    log.info("Removing ldap instance.")
    instance_name = "-".join(constants.CA_INSTANCE_NAME.split("-")[:-1])
    res = ansible_module.command('dsctl slapd-{}-testingmaster remove --do-it'.format(instance_name))
    for r in res.values():
        assert r['rc'] == 0
        log.info("Removed ldap instance.")


@pytest.mark.skipif("TOPOLOGY != 0")
def test_bug_1489256_jss_should_support_rsa_with_oaep_padding(ansible_module, setup_fixture):
    """
    :Title: Bug 1489256 - [RFE] jss should support RSA with OAEP padding and Bug 1883656 - [RFE] Add OAEP as a KeyWrap algorithm for KRA in Dogtag PKI
    :Description: Bug 1489256 - [RFE] jss should support RSA with OAEP padding and Bug 1883656 - [RFE] Add OAEP as a KeyWrap algorithm for KRA in Dogtag PKI
    :id: 2d598525-b61c-4212-9de9-0666e41968dc
    :Requirement: RSA OAEP : Provide RSA OAEP encryption for RSA PSS signatures
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Install CA, Install KRA
        2. Add 'keyWrap.useOAEP=true' in both instances CS.cfg and restart the instance.
        3. Use CRMFPopClient to create a CSR to be approved and executed by the CA: CRMFPopClient -d . -p xxxxxxxx -oaep -n "cn=my prisingh 102720, uid=myprisingh" -q POP_SUCCESS -t true -b kra.transport -w "AES KeyWrap/Padding"  -v -l 2048  -o crmf2.req
        4. Submit the generated CSR to caServerCert profile with 'ca-cert-request-submit'
        5. Approve the request
        6. Execute PKI client-cert-request with --oaep parameter and approve the request
        7. Check the key is archived with 'RSAES-OAEP' padding in KRA debug log
    :ExpectedResults:
        1. Key archival should be successful with 'RSAES-OAEP' padding
    :Automated: yes
    """
    temp_dir = tempfile.mkdtemp(suffix="_pki", prefix="test_")

    # setup

    ansible_module.command('pki -d {} -c {} client-init '
                               '--force'.format(temp_dir, constants.CLIENT_DATABASE_PASSWORD))
    log.info("Initialize client dir: {}".format(temp_dir))
    command = 'pki -d {} -c {} -p {} client-cert-import --ca-server RootCA'.format(temp_dir,
                                                                                   constants.CLIENT_DATABASE_PASSWORD,
                                                                                   constants.CA_HTTPS_PORT)
    ansible_module.expect(command=command,responses={"Trust this certificate (y/N)?": "y"})
    log.info("Imported RootCA cert.")

    ansible_module.command('pki -d {} -c {} client-cert-import --pkcs12 {} '
                               '--pkcs12-password {}'.format(temp_dir, constants.CLIENT_DATABASE_PASSWORD,
                                                             constants.CA_CLIENT_DIR + "/ca_admin_cert.p12",
                                                             constants.CLIENT_PKCS12_PASSWORD))
    log.info("Imported CA Admin Cert.")

    ansible_module.command('pki -d {} -c {} client-cert-import --pkcs12 {} '
                               '--pkcs12-password {}'.format(temp_dir, constants.CLIENT_DATABASE_PASSWORD,
                                                             constants.KRA_CLIENT_DIR + "/kra_admin_cert.p12",
                                                             constants.CLIENT_PKCS12_PASSWORD))
    log.info("Imported KRA Admin Cert.")

    subject = "CN=my prisingh,UID=myprisingh"
    subject2 = "UID=myprisinghoaep"
    transport_file = '/tmp/transport.pem'

    get_transport = ansible_module.pki(cli='ca-cert-find',
                                       nssdb=temp_dir,
                                       dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                       protocol='http',
                                       port=constants.CA_HTTP_PORT,
                                       certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                       extra_args='--name "DRM Transport Certificate"')

    for r in get_transport.values():
        if r['rc'] == 0:
            get_no = re.findall("Serial Number.*", r['stdout'])
            transport_no = get_no[0].split(":")[1].strip()
            log.info("Got transport serial: {}".format(transport_no))

            get_cert = ansible_module.pki(cli='ca-cert-show',
                                          nssdb=temp_dir,
                                          dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                          protocol='http',
                                          port=constants.CA_HTTP_PORT,
                                          certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                          extra_args='{} --output {}'.format(transport_no,
                                                                             transport_file))
            for r1 in get_cert.values():
                assert r1['rc'] == 0
                log.info("Got transport cert: {}".format(transport_file))

    # Add 'keyWrap.useOAEP=true' in both instance CS.cfg

    ansible_module.lineinfile(path=ca_cfg_path, insertafter='^jss.ssl.sslserver', line='keyWrap.useOAEP=true')
    ansible_module.lineinfile(path=kra_cfg_path, insertafter='^CrossCertPair.ldap', line='keyWrap.useOAEP=true')
    ansible_module.replace(path=kra_cfg_path, regexp='debug.level=10', replace='debug.level=0')


    # Restart both the server
    ansible_module.command('pki-server restart {}'.format(constants.CA_INSTANCE_NAME))
    time.sleep(10)
    ansible_module.command('pki-server restart {}'.format(constants.KRA_INSTANCE_NAME))
    time.sleep(10)

    # PKI client-cert-request with --oaep
    cert_req = ansible_module.command('pki -d {} -c {} -p {} -n "{}" client-cert-request "{}" --oaep --type crmf'.format(temp_dir,
                                                                                                                         constants.CLIENT_DATABASE_PASSWORD,
                                                                                                                         constants.CA_HTTPS_PORT, constants.CA_ADMIN_NICK, subject2))
    for r in cert_req.values():
        if r['rc'] == 0:
            get_req_no = re.findall('Request ID:.*', r['stdout'])
            req_no = get_req_no[0].split(":")[1].strip()
            log.info("Created certificate request with --oaep param: {}".format(req_no))
        else:
            log.error(r['stdout'])
            log.error(r['stderr'])
            pytest.fail()


    # Approve the request
    cmd = 'pki -d {} -c {} -p {} -n "{}" ca-cert-request-approve {}'.format(temp_dir,
                                                                  constants.CLIENT_DATABASE_PASSWORD,
                                                                  constants.CA_HTTPS_PORT, constants.CA_ADMIN_NICK, req_no)
    approve_req = ansible_module.expect(command=cmd,responses={"Are you sure (y/N)?": "y"})
    for r in approve_req.values():
        assert r['rc'] == 0
        get_serial_no = re.findall("Certificate ID:.*", r['stdout'])
        serial_no = get_serial_no[0].split(":")[1].strip()
        log.info("Certificate request approved for PKI --oaep param: {}".format(serial_no))

    # Generate CRMF request with OAEP padding
    cmd = 'CRMFPopClient -d {} -p {} -oaep -n "{}" -q POP_SUCCESS -b {} -w "AES KeyWrap/Padding" -v -l 2048 -o /tmp/crmf.req'.format(temp_dir, constants.CLIENT_DATABASE_PASSWORD, subject, transport_file)
    log.info("Running command: {}".format(cmd))

    cmd_out = ansible_module.shell(cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Using key wrap algorithm: AES KeyWrap/Padding" in result['stdout']
            log.info("Successfully generated CSR with OAEP padding")
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Submit CSR to caServerCert profile
    submit_req = ansible_module.pki(cli='ca-cert-request-submit',
                                     nssdb=temp_dir,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     protocol='https',
                                     port=constants.CA_HTTPS_PORT,
                                     certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                     extra_args='--csr-file {} --profile caServerCert --request-type crmf'.format(
                                         '/tmp/crmf.req'))
    for r in submit_req.values():
        if r['rc'] == 0:
            assert 'Submitted certificate request' in r['stdout']
            get_req_no = re.findall("Request ID:.*", r['stdout'])
            req_no = get_req_no[0].split(":")[1].strip()
            log.info("Successfully submitted CSR and got request ID: {}".format(req_no))
        else:
            log.error(r['stdout'])
            log.error(r['stderr'])
            pytest.fail()

    # Approve the request
    cmd = 'pki -d {} -c {} -p {} -n "{}" ca-cert-request-approve {}'.format(temp_dir,
                                                                  constants.CLIENT_DATABASE_PASSWORD,
                                                                  constants.CA_HTTPS_PORT, constants.CA_ADMIN_NICK, req_no)
    approve_req = ansible_module.expect(command=cmd,responses={"Are you sure (y/N)?": "y"})
    for r in approve_req.values():
        assert r['rc'] == 0
        get_serial_no = re.findall("Certificate ID:.*", r['stdout'])
        serial_no = get_serial_no[0].split(":")[1].strip()
        log.info("Certificate request approved for CRMFPopClient -oaep param: {}".format(serial_no))

    # Grep 'RSAES-OAEP' in KRA debug log
    logs = ansible_module.command('cat /var/log/pki/{}/kra/debug.{}.log'.format(constants.KRA_INSTANCE_NAME, date))
    for result in logs.values():
        if 'FINE' in result['stdout']:
            assert re.search("FINE:\s+CryptoUtil.unwrap KeyWrapAlg:\s+RSAES-OAEP", result['stdout'])
            assert re.search("FINE:\s+CryptoUtil.wrapUsingPublicKey\s+KeyWrapAlg:\s+RSAES-OAEP", result['stdout'])
            log.info("Successfully found the 'RSAES-OAEP' padding in KRA debug log")
        else:
            log.error('Failed to enable the FINE debug log')
            pytest.fail()

    # Find and validate the archived key
    command = 'pki -d {} -c {} -p {} -n "{}" kra-key-find'.format(temp_dir,
                                                                  constants.CLIENT_DATABASE_PASSWORD,
                                                                  constants.KRA_HTTPS_PORT, constants.KRA_ADMIN_NICK)
    find_key = ansible_module.expect(command=command,responses={"Trust this certificate (y/N)?": "y"})

    for r in find_key.values():
        assert r['rc'] == 0
        assert "Owner: {}".format(subject) in r['stdout']
        assert "Owner: {}".format(subject2) in r['stdout']
        log.info("Key archived successfully.")
