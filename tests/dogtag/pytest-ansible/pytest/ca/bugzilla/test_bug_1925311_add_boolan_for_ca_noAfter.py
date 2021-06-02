#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   Description: Bug 1925311 - [RFE] Add a Boolean to Not
#               Allow a CA Certificate Issued Past Issuing CA's Validity
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   Author: Deepak Punia <dpunia@redhat.com>
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Copyright Red Hat, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""

import sys
import os
import logging
import pytest
import datetime, time
import random
import re
import requests

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)

if os.path.isfile('/tmp/test_dir/constants.py'):
    import sys

    sys.path.append('/tmp/test_dir')
    import constants

ca_url = 'https://{}:{}'.format(constants.MASTER_HOSTNAME, constants.CA_HTTPS_PORT)
BASE_DIR = '/var/lib/pki/{}/ca'.format(constants.CA_INSTANCE_NAME)
profile_path = BASE_DIR + '/profiles/ca/caCACert.cfg'
ca_cfg_path = BASE_DIR + '/conf/CS.cfg'
ca_debug_path = '/var/lib/pki/{}/logs/ca/debug.{}.log'.format(constants.CA_INSTANCE_NAME,
                                                              datetime.datetime.now().strftime("%Y-%m-%d"))
profile_parm = 'policyset.caCertSet.2.default.params.bypassCAnotafter={}'
caValidityDefaultImpl = 'policyset.caCertSet.2.default.class_id=caValidityDefaultImpl'
validityDefaultImpl = 'policyset.caCertSet.2.default.class_id=validityDefaultImpl'
profile_const_range = 'policyset.caCertSet.2.constraint.params.range'
profile_defalt_range = 'policyset.caCertSet.2.default.params.range'
cs_cfg_parm = 'ca.enablePastCATime_caCert={}'
csr_path = '/tmp/testCA.csr'


def restart_instance(ansible_module, instance=constants.CA_INSTANCE_NAME):
    command = 'systemctl restart pki-tomcatd@{}'.format(instance)
    time.sleep(10)
    out = ansible_module.command(command)
    for res in out.values():
        assert res['rc'] == 0


def convert_string_to_datetime(date_str):
    date_split = date_str[0].split("After: ")[1].split(' ')
    date_split.pop(-2)
    return datetime.datetime.strptime(' '.join(date_split), "%a %b %d %H:%M:%S %Y")


def test_bug_1925311_allow_to_bypass_ca_noAfter(ansible_module):
    """
    :id: 03e97138-0182-40da-a416-cbc47d2b8240
    :Title: Bug 1925311 - Add parameter to allow to bypass the CA's notafter
    :Description: Bug 1925311 - Should allow to bypass the CA's notafter if both conditions are satisfied
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :Setup:
        1. Install a CA
        2. Edit profile caCACert.cfg so that it has the line policyset.caCertSet.2.default.params.bypassCAnotafter=true under policyset.caCertSet.2.default.class_id=caValidityDefaultImpl
        3. Edit CS.cfg to add ca.enablePastCATime_caCert=true
        4. restart CA
    :Steps:
        1. generate a csr for a ca signing cert that will pass your current CA's signing cert notAfter date
        2. Paste the cfuCA.csr into EE web portal profile caCACert and submit
        3. agent approve the request
    :ExpectedResults:
        1. observe that the the issued cert contains a notAfter date as requested, passing that of the signing CA's
    :Automated: Yes
    :CaseComponent: \-
    """
    crt_cn = 'CN=Test CA Cert{}'.format(random.randint(1, 999))

    # Setup part required by gui request.
    ansible_module.shell("openssl pkcs12 -in /opt/{}/ca_admin_cert.p12 "
                         "-out /tmp/auth_cert.pem -nodes -passin pass:{}".format(constants.CA_INSTANCE_NAME,
                                                                                 constants.CLIENT_DATABASE_PASSWORD))
    ansible_module.fetch(src="/tmp/auth_cert.pem", dest="/tmp/auth_cert.pem", flat="yes")
    ansible_module.fetch(src='/tmp/rootCA.pem', dest='/tmp/rootCA.pem', flat="yes")

    # Updating config parameter to execute test
    ansible_module.lineinfile(path=profile_path, insertafter=caValidityDefaultImpl, line=profile_parm.format('true'),
                              state='present')
    for parms in profile_const_range, profile_defalt_range:
        ansible_module.replace(path=profile_path, regexp='{}=.*'.format(parms), replace='{}=10341'.format(parms))

    ansible_module.lineinfile(path=ca_cfg_path, line=cs_cfg_parm.format('true'), state='present')
    ansible_module.lineinfile(path=ca_cfg_path, regexp="ca.enableNonces=true", line="ca.enableNonces=false")
    restart_instance(ansible_module)
    log.info("Restarted instance : {}".format(constants.CA_INSTANCE_NAME))

    # Creating csr for certificate request
    ansible_module.shell('echo "{}" > /tmp/pass.txt'.format(constants.CLIENT_DATABASE_PASSWORD))
    ansible_module.shell('echo $(seq 1 100) | certutil -d {} -f /tmp/pass.txt -R -s "{}" -o {} -a -v 340'
                         .format(constants.NSSDB, crt_cn, csr_path))

    pop_out = ansible_module.shell("sed -i '1,11d;$d' {}".format(csr_path))
    for result in pop_out.values():
        if result['rc'] == 0:
            ansible_module.fetch(src=csr_path, dest=csr_path, flat="yes")
            encoded_cert = open(csr_path, "r").read()
        else:
            pytest.fail("Failed to run: {}".format("".join(result['cmd'])))

    # Adding sleep timer
    ansible_module.shell('sleep 10')

    # Create Certificate Request with Requests Module
    req_data = {
        'cert_request_type': 'pkcs10',
        'cert_request': '{}'.format(encoded_cert),
        'profileId': 'caCACert'
    }
    response = requests.post(ca_url + "/ca/ee/ca/profileSubmit", data=req_data, verify='/tmp/rootCA.pem',
                             cert='/tmp/auth_cert.pem')
    if response.status_code == 200:
        request = re.findall('requestList.requestId="[\w]*"', response.content)
        request_id = request[0].split("=")[1].strip().replace("\"", "")
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()

    # approve certificate request
    approve_cert = ansible_module.pki(cli='ca-cert-request-approve',
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.CA_HTTPS_PORT,
                                      protocol='https',
                                      certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                      extra_args='{} --force'.format(request_id))
    for result in approve_cert.values():
        if result['rc'] == 0:
            serial = re.findall('Certificate ID: [\w]*', result['stdout'])
            serial_id = serial[0].split(":")[1].strip().replace("\"", "")
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.fail()

    show_cert = ansible_module.pki(cli='ca-cert-show',
                                   nssdb=constants.NSSDB,
                                   dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                   port=constants.CA_HTTPS_PORT,
                                   protocol='https',
                                   certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                   extra_args='{}'.format(serial_id))
    for result in show_cert.values():
        if result['rc'] == 0:
            date_str = re.findall('Not Valid After: .*', result['stdout'])
            crt_no_aftr_dt = convert_string_to_datetime(date_str)
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.fail()

    shw_sign_crt = ansible_module.pki(cli='ca-cert-find',
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.CA_HTTPS_PORT,
                                      protocol='https',
                                      certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                      extra_args='--name "CA Signing Certificate"')
    for result in shw_sign_crt.values():
        if result['rc'] == 0:
            date_str = re.findall('Not Valid After: .*', result['stdout'])
            sign_crt_no_aftr_dt = convert_string_to_datetime(date_str)
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.fail()

    # check issued cert contains a notAfter date as requested, passing that of the signing CA's
    if crt_no_aftr_dt > sign_crt_no_aftr_dt:
        log.info("Test Pass: CA Bypass the notAfter date")
    else:
        log.info("Test Fail: CA Not Bypass the notAfter date")
        pytest.fail()


def test_bug_1925311_bypass_ca_noAfter_caValidityDefault_plugin_not_use(ansible_module):
    """
    :id: 14cc7d4e-efa6-4786-b438-093d1c7fbd90
    :Title: Bug 1925311 - Bypass the CA's notAfter except the caValidityDefault plugin is not used
    :Description: Bug 1925311 - Bypass the CA's notAfter except the caValidityDefault plugin is not used
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :Setup:
        1. Install a CA
        2. Remove the caValidityDefaultImpl lines for def and constraint in the caCACert.cfg profile
        3. Edit CS.cfg to add ca.enablePastCATime_caCert=true
        4. restart CA
    :Steps:
        1. generate a csr for a ca signing cert that will pass your current CA's signing cert notAfter date
        2. Paste the cfuCA.csr into EE web portal profile caCACert and submit
        3. agent approve the request
    :ExpectedResults:
        1. observe that the the issued cert contains a notAfter date as requested, passing that of the signing CA's
    :Automated: Yes
    :CaseComponent: \-
    """
    # Updating config parameter to execute test
    crt_cn = 'CN=Test CA Cert{}'.format(random.randint(1, 999))
    ansible_module.lineinfile(path=profile_path, line=profile_parm.format('true'), state='absent')
    ansible_module.lineinfile(path=ca_cfg_path, line=cs_cfg_parm.format('true'), state='present')
    ansible_module.replace(path=profile_path, regexp=caValidityDefaultImpl, replace=validityDefaultImpl)
    restart_instance(ansible_module)
    log.info("Restarted instance : {}".format(constants.CA_INSTANCE_NAME))

    # Creating csr for certificate request
    ansible_module.shell('echo $(seq 1 100) | certutil -d {} -f /tmp/pass.txt -R -s "{}" -o {} -a -v 340'
                         .format(constants.NSSDB, crt_cn, csr_path))
    pop_out = ansible_module.shell("sed -i '1,11d;$d' {}".format(csr_path))
    for result in pop_out.values():
        if result['rc'] == 0:
            ansible_module.fetch(src=csr_path, dest=csr_path, flat="yes")
            encoded_cert = open(csr_path, "r").read()
        else:
            pytest.fail("Failed to run: {}".format("".join(result['cmd'])))

    # Adding sleep timer
    ansible_module.shell('sleep 10')

    # Create Certificate Request with Requests Module
    req_data = {
        'cert_request_type': 'pkcs10',
        'cert_request': '{}'.format(encoded_cert),
        'profileId': 'caCACert'
    }
    response = requests.post(ca_url + "/ca/ee/ca/profileSubmit", data=req_data, verify='/tmp/rootCA.pem',
                             cert='/tmp/auth_cert.pem')
    if response.status_code == 200:
        request = re.findall('requestList.requestId="[\w]*"', response.content)
        request_id = request[0].split("=")[1].strip().replace("\"", "")
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()

    # approve certificate request
    approve_cert = ansible_module.pki(cli='ca-cert-request-approve',
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.CA_HTTPS_PORT,
                                      protocol='https',
                                      certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                      extra_args='{} --force'.format(request_id))
    for result in approve_cert.values():
        if result['rc'] == 0:
            serial = re.findall('Certificate ID: [\w]*', result['stdout'])
            serial_id = serial[0].split(":")[1].strip().replace("\"", "")
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.fail()

    show_cert = ansible_module.pki(cli='ca-cert-show',
                                   nssdb=constants.NSSDB,
                                   dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                   port=constants.CA_HTTPS_PORT,
                                   protocol='https',
                                   certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                   extra_args='{}'.format(serial_id))
    for result in show_cert.values():
        if result['rc'] == 0:
            date_str = re.findall('Not Valid After: .*', result['stdout'])
            crt_no_aftr_dt = convert_string_to_datetime(date_str)
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.fail()

    shw_sign_crt = ansible_module.pki(cli='ca-cert-find',
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.CA_HTTPS_PORT,
                                      protocol='https',
                                      certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                      extra_args='--name "CA Signing Certificate"')
    for result in shw_sign_crt.values():
        if result['rc'] == 0:
            date_str = re.findall('Not Valid After: .*', result['stdout'])
            sign_crt_no_aftr_dt = convert_string_to_datetime(date_str)
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.fail()

    # check issued cert contains a notAfter date as requested, passing that of the signing CA's
    if crt_no_aftr_dt > sign_crt_no_aftr_dt:
        log.info("Test Pass: CA Bypass the notAfter date")
    else:
        log.info("Test Fail: CA Not Bypass the notAfter date")
        pytest.fail()


def test_bug_1925311_not_allow_to_bypass_ca_noAfter(ansible_module):
    """
    :id: 7d25a56c-62fb-4306-9050-07de4fd676e3
    :Title: Bug 1925311 - should not be enough to bypass the CA's notafter
    :Description: Bug 1925311 - if bypassCAnotafter=true for caValidityDefault plugin in the profile used, it should not be enough to bypass the CA's notafter
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :Setup:
        1. Install a CA
        2. Edit profile caCACert.cfg so that it has the line policyset.caCertSet.2.default.params.bypassCAnotafter=true under policyset.caCertSet.2.default.class_id=caValidityDefaultImpl
        3. no need to add the ca.enablePastCATime_caCert=false line in CS.cfg, as that's the default
        4. restart CA
    :Steps:
        1. generate a csr for a ca signing cert that will pass your current CA's signing cert notAfter date
        2. Paste the cfuCA.csr into EE web portal profile caCACert and submit
        3. agent approve the request
    :ExpectedResults:
        1. observe that the the issued cert contains a notAfter date matches that of the signing CA's
    :Automated: Yes
    :CaseComponent: \-
    """
    crt_cn = 'CN=Test CA Cert{}'.format(random.randint(1, 999))
    ansible_module.replace(path=profile_path, regexp=validityDefaultImpl, replace=caValidityDefaultImpl)
    ansible_module.lineinfile(path=profile_path, insertafter=caValidityDefaultImpl, line=profile_parm.format('true'),
                              state='present')
    ansible_module.lineinfile(path=ca_cfg_path, line=cs_cfg_parm.format('true'), state='absent')
    restart_instance(ansible_module)
    log.info("Restarted instance : {}".format(constants.CA_INSTANCE_NAME))

    ansible_module.shell('echo $(seq 1 100) | certutil -d {} -f /tmp/pass.txt -R -s "{}" -o {} -a -v 340'
                         .format(constants.NSSDB, crt_cn, csr_path))
    pop_out = ansible_module.shell("sed -i '1,11d;$d' {}".format(csr_path))
    for result in pop_out.values():
        if result['rc'] == 0:
            ansible_module.fetch(src=csr_path, dest=csr_path, flat="yes")
            encoded_cert = open(csr_path, "r").read()
        else:
            pytest.fail("Failed to run: {}".format("".join(result['cmd'])))

    # Adding sleep timer
    ansible_module.shell('sleep 10')

    # Create Certificate Request with Requests Module
    req_data = {
        'cert_request_type': 'pkcs10',
        'cert_request': '{}'.format(encoded_cert),
        'profileId': 'caCACert'
    }
    response = requests.post(ca_url + "/ca/ee/ca/profileSubmit", data=req_data, verify='/tmp/rootCA.pem',
                             cert='/tmp/auth_cert.pem')
    if response.status_code == 200:
        request = re.findall('requestList.requestId="[\w]*"', response.content)
        request_id = request[0].split("=")[1].strip().replace("\"", "")
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()

    approve_cert = ansible_module.pki(cli='ca-cert-request-approve',
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.CA_HTTPS_PORT,
                                      protocol='https',
                                      certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                      extra_args='{} --force'.format(request_id))
    for result in approve_cert.values():
        if result['rc'] == 0:
            serial = re.findall('Certificate ID: [\w]*', result['stdout'])
            serial_id = serial[0].split(":")[1].strip().replace("\"", "")
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.fail()

    show_cert = ansible_module.pki(cli='ca-cert-show',
                                   nssdb=constants.NSSDB,
                                   dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                   port=constants.CA_HTTPS_PORT,
                                   protocol='https',
                                   certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                   extra_args='{}'.format(serial_id))
    for result in show_cert.values():
        if result['rc'] == 0:
            date_str = re.findall('Not Valid After: .*', result['stdout'])
            crt_no_aftr_dt = convert_string_to_datetime(date_str)
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.fail()

    shw_sign_crt = ansible_module.pki(cli='ca-cert-find',
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.CA_HTTPS_PORT,
                                      protocol='https',
                                      certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                      extra_args='--name "CA Signing Certificate"')
    for result in shw_sign_crt.values():
        if result['rc'] == 0:
            date_str = re.findall('Not Valid After: .*', result['stdout'])
            sign_crt_no_aftr_dt = convert_string_to_datetime(date_str)
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.fail()

    if crt_no_aftr_dt == sign_crt_no_aftr_dt:
        log.info("Test Pass: notAfter date matches with signing CA's")
    else:
        log.info("Test Fail: notAfter date not matches with signing CA's")
        pytest.fail()

    # Cleanup part
    ansible_module.lineinfile(path=profile_path, line=profile_parm.format('true'), state='absent')
    ansible_module.lineinfile(path=ca_cfg_path, regexp="ca.enableNonces=false", line="ca.enableNonces=true")
    restart_instance(ansible_module)
    log.info("Restarted instance : {}".format(constants.CA_INSTANCE_NAME))

    for file in csr_path, '/tmp/auth_cert.pem', '/tmp/pass.txt':
        ansible_module.file(path=file, state='absent')
