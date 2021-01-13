#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Bug 1392616 - KRA key recovery cli kra-key-retrieve generates an invalid p12 file
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Deepak Punia <dpunia@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Copyright Red Hat, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""
import os
import sys
import logging
import pytest
from pki.testlib.common import utils
import re
import time

try:
    from pki.testlib.common import constants
except Exception:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
userop = utils.UserOperations(nssdb=constants.NSSDB, db_pass=constants.CLIENT_DATABASE_PASSWORD)
template_name = "retrieveKey.template"
cert_file = "b64_cert"


def test_bug_1392616_kra_key_recovery_cli_generates_p12_file(ansible_module):
    """
    :id: 2b115260-a99c-42fe-8e63-b1c58ef51194
    :Title: Bug 1392616 - KRA key recovery cli kra-key-retrieve generates p12 file
    :Description: Bug 1392616 - KRA key recovery cli kra-key-retrieve generates an invalid p12 file
    :Requirement: RHCS-REQ Key Management KRA: DRM Key Rotation
    :Setup:
        1. Install CA, KRA
    :Steps:
        1. Generate CRMF request
        2. Submit/approve request
        3. Verify key archived
        4. Initiate recovery & Approve Recovery
        5. Retrieve template & recover the key
        6. Verify PKCS12
    :ExpectedResults:
        1. Should able to submit/approve the crmf request successfully.
        2. Key recovery and verification should be successful
    :Automated: Yes
    :CaseComponent: \-
    """
    # restart services before execusting test
    for service in constants.CA_INSTANCE_NAME, constants.KRA_INSTANCE_NAME:
        ansible_module.command("pki-server restart {}".format(service))
        time.sleep(20)

    # Generate CRMF request
    request_id = userop.create_certificate_request(ansible_module, subject='CN=foo1', request_type='crmf',
                                                   profile='caOtherCert')
    cert_id = userop.process_certificate_request(ansible_module, request_id=request_id, action='approve')

    if cert_id is None:
        #  Observed that Sometime first attempt of request approval failed
        # because of intermittent network issue, then retrying again for approval.
        time.sleep(5)
        cert_id = userop.process_certificate_request(ansible_module, request_id=request_id, action='approve')

    ansible_module.pki(cli='ca-cert-show',
                       nssdb=constants.NSSDB,
                       dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                       port=constants.CA_HTTPS_PORT,
                       protocol='https',
                       certnick="'{}'".format(constants.CA_ADMIN_NICK),
                       extra_args=' {} --output {}'.format(cert_id, cert_file))

    # Verify key archived
    find_out = ansible_module.pki(cli='kra-key-find',
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  protocol='https',
                                  port=constants.KRA_HTTPS_PORT,
                                  hostname=constants.MASTER_HOSTNAME,
                                  certnick='"{}"'.format(constants.KRA_ADMIN_NICK))
    for result in find_out.values():
        if result['rc'] == 0:
            key_request_id = re.findall('Key ID:.*', result['stdout'])
            key_id = key_request_id[-1].split(":")[1].strip()
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Initiate recovery
    recover_out = ansible_module.pki(cli='kra-key-recover',
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     protocol='https',
                                     port=constants.KRA_HTTPS_PORT,
                                     hostname=constants.MASTER_HOSTNAME,
                                     certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                     extra_args='--keyID {}'.format(key_id))
    for result in recover_out.values():
        if result['rc'] == 0:
            key_request_id = re.findall('Request ID:.*', result['stdout'])
            request_id = key_request_id[0].split(":")[1].strip()
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Approve Recovery
    review_out = ansible_module.pki(cli='kra-key-request-review',
                                    nssdb=constants.NSSDB,
                                    dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                    protocol='https',
                                    port=constants.KRA_HTTPS_PORT,
                                    hostname=constants.MASTER_HOSTNAME,
                                    certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                    extra_args='{} --action approve'.format(request_id))
    for result in review_out.values():
        if result['rc'] == 0:
            key_request_id = re.findall('Request ID:.*', result['stdout'])
            request_id = key_request_id[0].split(":")[1].strip()

            key_id = re.findall('Key ID:.*', result['stdout'])
            key_id = key_id[0].split(":")[1].strip()
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Retrieve recovery template
    ansible_module.pki(cli='kra-key-template-show',
                       nssdb=constants.NSSDB,
                       dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                       protocol='https',
                       port=constants.KRA_HTTPS_PORT,
                       hostname=constants.MASTER_HOSTNAME,
                       certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                       extra_args='retrieveKey --output {}'.format(template_name))

    # Retrieve b64 certificate
    cert_out = ansible_module.shell("cat {} | tr -d '\r\n' | sed -e 's/-----BEGIN CERTIFICATE-----//' "
                                    "-e 's/-----END CERTIFICATE-----//'".format(cert_file))
    for result in cert_out.values():
        if result['rc'] == 0:
            b64_cert = re.findall('.*', result['stdout'])[0]
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # edit recovery template
    dict = {
        '"keyId">.*</Attribute>': '"keyId">{}</Attribute>'.format(key_id),
        '"requestId">.*</Attribute>': '"requestId">{}</Attribute>'.format(request_id),
        '"nonceData">.*</Attribute>': '"nonceData"></Attribute>',
        '"passphrase">.*</Attribute>': '"passphrase">{}</Attribute>'.format(constants.CLIENT_DATABASE_PASSWORD),
        '"sessionWrappedPassphrase">.*</Attribute>': '"sessionWrappedPassphrase"></Attribute>',
        '"transWrappedSessionKey">.*</Attribute>': '"transWrappedSessionKey"></Attribute>',
        '"certificate">.*</Attribute>': '"certificate">{}</Attribute>'.format(b64_cert)
    }
    for key, value in dict.items():
        ansible_module.replace(path=template_name, regexp=key, replace=value)

    # retrieve .p12.b64 key
    key_out = ansible_module.pki(cli='kra-key-retrieve',
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 protocol='https',
                                 port=constants.KRA_HTTPS_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args='--input {}'.format(template_name))
    for result in key_out.values():
        if result['rc'] == 0:
            raw_cert = re.findall('<p12Data>.*</p12Data>', result['stdout'])
            b64_cert = raw_cert[0].split(">")[1].split("<")[0]
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # convert key from .p12.b64 key to .p12 format
    ansible_module.copy(content=b64_cert, dest="cert.p12.b64")
    ansible_module.command("AtoB cert.p12.b64 cert.p12")

    # import key to the database.
    import_out = ansible_module.command('pk12util -d {} -i cert.p12 -K {} -W {}'.format(constants.NSSDB,
                                                                                        constants.CLIENT_DATABASE_PASSWORD,
                                                                                        constants.CLIENT_DATABASE_PASSWORD))
    for result in import_out.values():
        if result['rc'] == 0:
            assert "PKCS12 IMPORT SUCCESSFUL" in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            log.info(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # cleaning
    for rfile in template_name, cert_file, 'cert.p12.b64', 'cert.p12':
        ansible_module.command('rm -Rivf {}'.format(rfile))
