#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI CERT CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki user commands needs to be tested:
#   pki cert-show , pki ca-cert-show
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Amol Kahat <akahat@redhat.com>
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

import logging
import os
import random
import subprocess
import re
import shutil
import sys
import tempfile
from lxml import etree

import pytest

from pki.testlib.common.utils import UserOperations

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

user_op = UserOperations(nssdb=constants.NSSDB)
log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
topology = constants.CA_INSTANCE_NAME.split("-")[-1]
cmd = 'ca-cert-request-show'
status = ['pending', 'cancel', 'reject', 'approve']
tenses = {'cancel': 'canceled',
          'pending': 'pending',
          'reject': 'rejected',
          'approve': 'approved',
          'assign': 'assigned',
          'update': 'updated'}


def construct_xml(xml_file, **kwargs):
    xml_obj = etree.parse(xml_file)
    root = xml_obj.getroot()
    new_xml_file = xml_file.split(".")[0] + "_m.xml"
    subject = kwargs.get('subject','/UID=testuser,CN=testuser')
    profile = kwargs.get('profile', 'caUserCert')
    try:
        if 'cert_request' not in kwargs.keys():
            raise KeyError("cert_request is not defined")
        sub = subject.split(",")
        param_dict = {
            'cert_request_type': kwargs.get('request_type', 'pkcs10'),
            'cert_request': kwargs['cert_request'],
            'subject': subject.replace('/', '')
        }

        for con in sub:
            if '=' in con:
                key = "sn_{}".format(con.split("=")[0].lower().replace('/', ''))
                value = con.split("=")[1]
                param_dict[key] = value
        if profile in ['caUserCert', 'caUserSMIMEcapCert', 'caDualCert',
                       'caDirBasedDualCert', 'caAgentFoobar']:
            try:
                for key, val in param_dict.items():
                    if key not in ['subject']:
                        text = root.xpath("//*[@name='{}']/Value/text()".format(key))
                        if text in [None, "", []] and text != val:
                            root.xpath("//*[@name='{}']/Value".format(key))[0].text = val
            except Exception as e:
                print(e)

        elif profile in ['AdminCert', 'caAgentServerCert', 'caCACert', 'caDirBasedDualCert',
                         'caDirPinUserCert', 'caDirUserCert']:
            keys = ['cert_request_type', 'cert_request']
            if profile == 'AdminCert':
                keys.append('subject')
            try:
                for key in keys:
                    text = root.xpath("//*[@name='{}']/Value/text()".format(key))
                    if text in [None, "", []] and text != param_dict[key]:
                        root.xpath("//*[@name='{}']/Value".format(key))[0].text = param_dict[key]
            except Exception as e:
                print(e)

        xml_obj.write(new_xml_file)
        return new_xml_file
    except Exception as e:
        print(e)
        exit(1)


@pytest.mark.parametrize('subcmd', ['', '--help', 'asdfa'])
def test_pki_ca_cert_request_show_help(ansible_module, subcmd):
    """
    :Title: Test pki ca-cert-request-show with '', 'asdfa' and --help
    :Description: This test will test pki ca-cert-request-show with '', 'asdfa' and --help
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-cert-request-show
        2. Run pki ca-cert-request-show --help
    :Expectedresults:
        1. It will show all the certificate requests.
        2. It will show all the certificate request cli options.
    """
    help_out = ansible_module.command("pki ca-cert-request-show {}".format(subcmd))

    for host, result in help_out.items():
        if result['rc'] == 0:
            assert 'usage: {} <Request ID> [OPTIONS...]'.format(cmd) in result['stdout']
            assert '--help   Show help options' in result['stdout']
        else:
            if subcmd == '':
                assert 'Error: Missing Certificate Request ID.' in result['stderr']
            else:
                assert 'Error: Invalid certificate request ID {}'.format(subcmd) in result['stderr']


@pytest.mark.parametrize('subcmd', ['hex', 'dec'])
def test_pki_ca_cert_request_show_with_different_no(ansible_module, subcmd):
    """
    :Title: Test pki ca-cert-request-show with different no like hex, and dec.
    :Description: Test pki ca-cert-request-show with different no like hex and dec, will expected
                  to show results for both no.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-cert-request show 0x1
        2. Run pki ca-cert-request show 1
    :Expectedresults:
        1. Command should show the request for hex and decimal number format.
    """
    userid = 'testuser1'
    subject = 'UID={},CN={}'.format(userid, userid)
    request_id = user_op.create_certificate_request(ansible_module,
                                                    subject=subject)
    log.info("Generated certificat request. Req ID: {}".format(request_id))
    if subcmd == 'hex':
        request_id = hex(int(request_id))
        log.info("Request ID in hex : {}".format(request_id))
    request_show = ansible_module.pki(cli=cmd,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      port=constants.CA_HTTP_PORT,
                                      extra_args='{}'.format(request_id))
    for result1 in request_show.values():
        log.info("Running : {}".format(result1['cmd']))
        if result1['rc'] == 0:
            assert 'Request ID:' in result1['stdout']
            assert 'Type: enrollment' in result1['stdout']
            assert 'Request Status: pending' in result1['stdout']
            assert 'Operation Result: success' in result1['stdout']
            log.info("Successfully displayed the request.")
        else:
            log.error("Failed to display the request.")
            pytest.xfail("Failed to run pki cert-request-show with {}.".format(subcmd))


@pytest.mark.parametrize('action', ['cancel', 'approve', 'reject'])
def test_pki_ca_cert_request_show_with_diff_renewal_req_action(ansible_module, action):
    """
    :Title: Submit renewal cert req and process it with cancel, approve, reject, update and assign.
    :Description:
        Submit renewal certificate request and process it with cancel, approve, reject, update
        and assign.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Submit Renewal certificate request and cancel it.
        2. Submit Renewal certificate request and approve it.
        3. Submit Renewal certificate request and reject it.
    :Expectedresults:
        1. Request should show it's status.
    """
    submitted_req = False
    request_id = None

    userid = 'testuser2'
    profile = 'caAgentFoobar'
    subject = 'UID={},CN={}'.format(userid, userid)

    cert_id = user_op.process_certificate_request(ansible_module, subject=subject,
                                                 profile=profile)
    log.info("Generated certificate with {} profile, Cert ID: {}".format(profile, cert_id))
    if cert_id:
        renew_request = ansible_module.pki(cli='ca-cert-request-submit',
                                           nssdb=constants.NSSDB,
                                           dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                           port=constants.CA_HTTP_PORT,
                                           extra_args='--renewal --serial {} '
                                                      '--profile {}'.format(cert_id, profile))
        for result1 in renew_request.values():
            log.info("Running: {}".format(result1['cmd']))
            if result1['rc'] == 0:
                assert 'Submitted certificate request' in result1['stdout']
                assert 'Request ID:' in result1['stdout']
                assert 'Type: renewal' in result1['stdout']
                assert 'Request Status: pending' in result1['stdout']
                assert 'Operation Result: success' in result1['stdout']

                submitted_req = True
                request_id = re.search('Request ID: [\w]*',
                                       result1['stdout']).group().encode('utf-8')
                request_id = request_id.split(":")[1].strip()
                log.info("Submitted renewal certificate request : {}".format(request_id))
                log.info("Getting request id : {}".format(request_id))
                log.info("Process request with action : {}".format(action))
                user_op.process_certificate_request(ansible_module, request_id=request_id,
                                                    action=action)
            else:
                log.error("Failed to submit renewal certificate request.")
                pytest.xfail("Failed to submit certificate renew request.")

    if submitted_req:
        approve_renew_req = ansible_module.pki(cli=cmd,
                                               nssdb=constants.NSSDB,
                                               dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                               port=constants.CA_HTTP_PORT,
                                               certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                               extra_args='{}'.format(request_id))
        for result in approve_renew_req.values():
            log.info("Running : {}".format(result['cmd']))
            if result['rc'] == 0:
                assert 'Certificate request "{}"'.format(request_id) in result['stdout']
                assert 'Type: renewal' in result['stdout']
                if action in ['update', 'assign']:
                    assert 'Request Status: pending' in result['stdout']
                elif action in ['approve']:
                    assert 'Request Status: complete' in result['stdout']
                    assert 'Certificate ID:' in result['stdout']
                elif action in ['cancel']:
                    assert 'Request Status: {}'.format(tenses[action])
                elif action in ['reject']:
                    assert 'Request Status: {}'.format(tenses[action])
                assert 'Operation Result: success' in result['stdout']
                log.info("Successfully displayed certificate request.")
            else:
                log.error("Failed to display certificate request.")
                pytest.xfail("Failed to run pki {} {} --action {}".format(cmd, cert_id, action))


@pytest.mark.parametrize('serial', [random.randint(1111, 99999), hex(random.randint(1111, 99999))])
def test_pki_ca_cert_request_show_with_invalid_serial_no(ansible_module, serial):
    """
    :Title: Test pki ca-cert-request-show with invalid serial number.
    :Description: This will test pki ca-cert-request with invalid serial number and as expected
                  it will throw an exception.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki ca-cert-request-show 234253223424
        2. pki ca-cert-request-show 0x3224821ad
    :Expectedresults:
        1. Will throw an error Request not found.
        2. Will throw an error Request not found.
    """
    request_out = ansible_module.pki(cli=cmd,
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     extra_args="{}".format(serial))
    for result in request_out.values():
        log.info("Running: {}".format(result['cmd']))
        if result['rc'] == 0:
            log.error("Failed to run pki {} {}".format(cmd, serial))
            pytest.xfail("Failed to run pki {} {}".format(cmd, serial))
        else:
            assert 'RequestNotFoundException: Request ID' in result['stderr']
            log.info("Successfully displayed certificate request.")


@pytest.mark.parametrize('profile', ['caUserCert', 'caDualCert', 'AdminCert', 'caCACert'])
def test_pki_ca_cert_request_show_with_different_profiles(ansible_module, profile):
    """
    :Title: Submit certificate request with different profiles and show it
    :Description: Submit certificate request with different profiles and show it.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Submit certificate request with caUserCert, caDualCert, AdminCert,
           caCACert.
    :Expectedresults:
        1. Certificate requests should get submitted successfully.
    """
    userid = 'testuser_{}'.format(profile)
    request_id = None
    if profile == 'caCACert':
        userid = 'CA'
        subject = '/CN=CA Signing Certificate,O={}'.format(constants.CA_SECURITY_DOMAIN_NAME)
    else:
        subject = '/UID={},CN={}'.format(userid, userid)
    xml_name = "{}.xml".format(userid, profile)
    remote_xml_profile = "/tmp/{}".format(xml_name)
    temp_dir = tempfile.mkdtemp('_ca', 'xml_', '/tmp/')
    xml_local_path = os.path.join(temp_dir, xml_name)
    cert_req_file = os.path.join(temp_dir, userid + ".req")
    profile_show_out = ansible_module.pki(cli='ca-cert-request-profile-show',
                                          nssdb=constants.NSSDB,
                                          dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                          port=constants.CA_HTTP_PORT,
                                          certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                          extra_args='{} --output {}'.format(profile,
                                                                             remote_xml_profile))
    for host, result in profile_show_out.items():
        if result['rc'] == 0:
            assert 'Enrollment Template for Profile "{}"'.format(profile) in result['stdout']
            assert 'Saved enrollment template for {} to {}'.format(profile, remote_xml_profile) in \
                   result['stdout']
            log.info("Getting cert req template: {}".format(remote_xml_profile))
        else:
            pytest.xfail("Failed to get xml file for profile {}".format(profile))

    log.info("Fetching xml file.")
    ansible_module.fetch(src=remote_xml_profile, dest=xml_local_path, flat='yes')
    log.info("Generating the RSA key, 2048 bit long.")
    gen_key = subprocess.call(['openssl', 'genrsa', '-out', '/{}/{}.key'.format(temp_dir, userid),
                               '2048'])
    if gen_key == 0:
        log.info("Generating the req using the key.")
        gen_req = subprocess.call(['openssl', 'req', '-new', '-sha512',
                                   '-key', '/{}/{}.key'.format(temp_dir, userid),
                                   '-out', cert_req_file,
                                   '-subj', '{}'.format(subject)])
        assert gen_req == 0

    req = open(cert_req_file, 'r').read()
    log.info("Constructing the xml file.")
    xml_file = construct_xml(xml_local_path, cert_request=req, subect=subject,
                             profile=profile)

    log.info("Putting xml file to the server.")
    ansible_module.copy(src=xml_file, dest='/tmp/')
    submit_request = ansible_module.pki(cli='ca-cert-request-submit',
                                        nssdb=constants.NSSDB,
                                        dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                        port=constants.CA_HTTP_PORT,
                                        extra_args="/tmp/{}".format(xml_file.split("/")[-1]))

    for result in submit_request.values():
        log.info("Running: {}".format(result['cmd']))
        if result['rc'] == 0:
            assert 'Submitted certificate request' in result['stdout']
            assert 'Request ID:' in result['stdout']
            assert 'Type: enrollment' in result['stdout']
            assert 'Request Status: pending' in result['stdout']
            assert 'Operation Result: success' in result['stdout']
            try:
                request_id = re.search('Request ID: [\w]*',
                                       result['stdout']).group().encode('utf-8')
                request_id = request_id.split(":")[1].strip()
            except Exception as e:
                print(e)
                sys.exit(1)
        else:
            pytest.xfail("Failed to run pki cert-request-submit with xml file.")

        if result['rc'] == 0:
            request_show = ansible_module.pki(cli=cmd,
                                              nssdb=constants.NSSDB,
                                              dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                              port=constants.CA_HTTP_PORT,
                                              extra_args='{}'.format(request_id))
            for result1 in request_show.values():
                if result1['rc'] == 0:
                    assert 'Request ID:' in result1['stdout']
                    assert 'Type: enrollment' in result1['stdout']
                    assert 'Request Status: pending' in result1['stdout']
                    assert 'Operation Result: success' in result1['stdout']
                else:
                    pytest.xfail("Failed to run pki cert-request-show with "
                                 "{}.".format(result1['cmd']))
    ansible_module.command('rm -rf {} /tmp/{}'.format(remote_xml_profile, xml_file.split("/")[-1]))
    shutil.rmtree(temp_dir)
