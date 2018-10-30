#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI USER-CERT CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki user commands needs to be tested:
#   pki user-cert
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
import random
import shutil
import subprocess
import tempfile

import os
import pytest
import re
import sys
from lxml import etree

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
cmd = 'ca-cert-request-submit'


def construct_xml(xml_file, **kwargs):
    xml_obj = etree.parse(xml_file)
    root = xml_obj.getroot()
    new_xml_file = xml_file.split(".")[0] + "_m.xml"
    subject = kwargs.get('subject', '/UID=testuser,CN=testuser')
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
                       'caDirBasedDualCert']:
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


@pytest.mark.parametrize('subcmd', (['', '--help', 'asdfa']))
def test_pki_ca_cert_request_submit_help(ansible_module, subcmd):
    """
    :Title: Test pki ca-cert-request-submit with '' and --help.
    :Description:
        This test will test ca-cert-request-submit with '' and --help options.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-cert-request-submit --help
        2. Run pki ca-cert-request-submit ''
        3. Run pki ca-cert-request-submit asdfa
    :Expectedresults:
        1. It will show help message.
        2. It will throw an error "Missing certificate file or Profile ID"
        3. It will throw an error.
    """
    help_cmd = 'pki -d {} -c {} -p {} -n "{}" {} ' \
               '{}'.format(constants.NSSDB, constants.CLIENT_DIR_PASSWORD, constants.CA_HTTP_PORT,
                           constants.CA_ADMIN_NICK, cmd, subcmd)
    help_out = ansible_module.command(help_cmd)

    for result in help_out.values():
        if result['rc'] == 0:
            assert 'usage: {} <filename> [OPTIONS...]'.format(cmd) in result['stdout']
            assert '--csr-file <path>       File containing the CSR' in result['stdout']
            assert '--help                  Show help options' in result['stdout']
            assert '--issuer-dn <DN>        Authority DN (host authority if omitted)' in \
                   result['stdout']
            assert '--issuer-id <ID>        Authority ID (host authority if omitted)' in \
                   result['stdout']
            assert '--password              Prompt password for request authentication' in \
                   result['stdout']
            assert '--profile <profile>     Certificate profile' in result['stdout']
            assert '--renewal               Submit renewal request' in result['stdout']
            assert '--request-type <type>   Request type (default: pkcs10)' in result['stdout']
            assert '--serial <number>       Serial number of certificate for renewal' in \
                   result['stdout']
            assert '--subject <DN>          Subject DN' in result['stdout']
            assert '--username <username>   Username for request authentication' in result['stdout']
        elif subcmd == 'asdfa':
            assert 'FileNotFoundException: asdfa (No such file or directory)' in result['stderr']
        else:
            assert 'Error: Missing request file or profile ID.' in result['stderr']


@pytest.mark.parametrize('profile', ['caUserCert', 'caDualCert', 'AdminCert', 'caCACert'])
def test_pki_ca_cert_request_submit_with_xml_file(ansible_module, profile):
    """
    :Title: Test pki ca-cert-request-submit with XML file with different profiles.
    :Description:
        This test will going to test this cli against the different profiles using profile xml 
        files.
        Userid , certificate request, subject and type will be stored to the file and it is going 
        to submit to the CA server using cli.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-profile-show <profile_name> --output <profile_name>.xml
        2. Generate key `openssl genrsa -out /tmp/testuser1.key 2048`
        3. Generate req `openssl req -new -sha512 -key /tmp/testuser1.key
           -out /tmp/testuser1.req -subj "UID=testuser1,CN=testuser1"
        4. Add the certificate request and subject parames to the xml profile file.
        5. Submit request using pki ca-cert-request-submit <profile_name>.xml.
    :Expectedresults:
        1. XML profile request should be successfully get submitted.
    """
    userid = 'testuser1'
    if profile == 'caCACert':
        userid = 'CA'
        subject = '/CN=CA Signing Certificate,O={}'.format(constants.CA_SECURITY_DOMAIN_NAME)
    else:
        subject = '/UID={},CN={}'.format(userid, userid)
    xml_name = "{}_{}.xml".format(userid, profile)
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
    submit_request = ansible_module.pki(cli=cmd,
                                        nssdb=constants.NSSDB,
                                        dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                        port=constants.CA_HTTP_PORT,
                                        extra_args="/tmp/{}".format(xml_file.split('/')[-1]))

    for result in submit_request.values():
        log.info("Running : {}".format(result['cmd']))
        if result['rc'] == 0:
            assert 'Submitted certificate request' in result['stdout']
            assert 'Request ID:' in result['stdout']
            assert 'Type: enrollment' in result['stdout']
            assert 'Request Status: pending' in result['stdout']
            assert 'Operation Result: success' in result['stdout']
        else:
            pytest.xfail("Failed to run pki cert-request-submit with xml file.")
    ansible_module.command('rm -rf {} {}'.format(remote_xml_profile, xml_file))
    shutil.rmtree(temp_dir)


@pytest.mark.parametrize('subcmd,error',
                         [('csr-file', "Error: Missing request file or profile ID."),
                          ('csr-file,profile,', "PKIException: Subject Name Not Found"),
                          ('csr-file,subject', 'Error: Missing request file or profile ID.'),
                          ('csr-file,profile,subject', 'all')])
def test_pki_ca_cert_request_submit_with_csr_file(ansible_module, subcmd, error):
    """
    :Title: Test pki ca-cert-request-submit with csr file.
    :Description:
        This test will test pki ca-cert-request-submit cli with --csr-file option. When user
        provide --csr-file option, at that time 2 more parameters are needs to provide for successful
        request.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Generate key `openssl genrsa -out /tmp/testuser2.key 2048`
        2. Generate req `openssl req -new -sha512 -key /tmp/testuser2.key
           -out /tmp/testuser2.req -subj "UID=testuser2,CN=testuser2"
        3. Run pki ca-cert-request-submit --csr-file /tmp/testuser2.req
        4. Run pki ca-cert-request-submit --csr-file /tmp/testuser2.req --profile caUserCert
        5. Run pki ca-cert-request-submit --csr-file /tmp/testuser2.req --profile caUserCert
           --subject "UID=testuser2,CN=testuser2"
    :Expectedresults:
        1. Only --csr-file option it should throw an error.
        2. For --csr-file and --profile it should throw an error.
        3. For --csr-file, --profile and --subject it should successfully submit the request.
    """
    userid = 'testuser2'
    subject = '/UID=testuser2,CN=testuser2'
    req_file = '/tmp/{}.req'.format(userid)
    key_file = '/tmp/{}.key'.format(userid)
    gen_key = subprocess.call(['openssl', 'genrsa', '-out', key_file, '2048'])
    if gen_key == 0:
        log.info("Generating the req using the key.")
        gen_req = subprocess.call(['openssl', 'req', '-new', '-sha512',
                                   '-key', key_file,
                                   '-out', req_file,
                                   '-subj', subject])
        assert gen_req == 0
        ansible_module.copy(src=req_file, dest='/tmp/')

    new_cmd = ''
    if ',' in subcmd:
        for sub_sub_cmd in subcmd.split(","):
            if sub_sub_cmd == 'csr-file':
                new_cmd += ' --csr-file ' + req_file
            elif sub_sub_cmd == 'profile':
                new_cmd += ' --profile caUserCert '
            elif sub_sub_cmd == 'subject':
                new_cmd += ' --subject "{}" '.format(subject.replace('/', ''))
    else:
        new_cmd = "--" + subcmd + " " + req_file

    submit_request = ansible_module.pki(
        cli=cmd,
        nssdb=constants.NSSDB,
        dbpassword=constants.CLIENT_DATABASE_PASSWORD,
        port=constants.CA_HTTP_PORT,
        extra_args="{}".format(new_cmd))

    for result in submit_request.values():
        log.info("Running: {}".format(result['cmd']))
        if result['rc'] == 255:
            assert error in result['stderr']
        elif result['rc'] == 0:
            assert 'Submitted certificate request' in result['stdout']
            assert 'Request ID:' in result['stdout']
            assert 'Type: enrollment' in result['stdout']
            assert 'Request Status: pending' in result['stdout']
            assert 'Operation Result: success' in result['stdout']
        else:
            pytest.xfail("Failed to run pki "
                         "{}".format(subcmd.format(req_file, subject.replace('/', ''))))


@pytest.mark.parametrize('profile', ['caUserCert', 'caDualCert',
                                     'AdminCert', 'caCACert', 'caDirUserCert'])
def test_pki_ca_cert_request_submit_with_csr_file_and_profile(ansible_module, profile):
    """
    :Title: Test pki ca-cert-request-submit with csr file and different profiles.
    :Description:
        Test pki ca-cert-request-submit with csr-file and different profiles will successfully
        submit the certificate request.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-cert-request-submit --csr-file /tmp/testuser3.req
           --subject "UID=testuser3,CN=testuser3" --profile caUserCert
        2. Execute 1 with caUserSMIMEcapCert, caDualCert, AdminCert, caCACert, caDirUserCert.
    :Expectedresults:
        1. For all the profiles request should be successfully get submitted.
    """
    userid = 'testuser2'
    if profile == 'caCACert':
        subject = '/CN=CA Signing Certificate,O={}'.format(constants.CA_SECURITY_DOMAIN_NAME)
    else:
        subject = '/UID={},CN={}'.format(userid, userid)
    req_file = '/tmp/{}.req'.format(userid)
    key_file = '/tmp/{}.key'.format(userid)
    gen_key = subprocess.call(['openssl', 'genrsa', '-out', key_file, '2048'])
    if gen_key == 0:
        log.info("Generating the req using the key.")
        gen_req = subprocess.call(['openssl', 'req', '-new', '-sha512',
                                   '-key', key_file,
                                   '-out', req_file,
                                   '-subj', subject])
        assert gen_req == 0
        ansible_module.copy(src=req_file, dest='/tmp/')
    submit_request = ansible_module.pki(
        cli=cmd,
        nssdb=constants.NSSDB,
        dbpassword=constants.CLIENT_DATABASE_PASSWORD,
        port=constants.CA_HTTP_PORT,
        extra_args="--csr-file {0} --profile {1} "
                   "--subject '{2}'".format(req_file, profile, subject.replace('/', '')))

    for result in submit_request.values():
        if result['rc'] == 0:
            assert 'Submitted certificate request' in result['stdout']
            assert 'Request ID:' in result['stdout']
            assert 'Type: enrollment' in result['stdout']
            assert 'Request Status: pending' in result['stdout']
            assert 'Operation Result: success' in result['stdout']
        else:
            if True:
                assert 'PKIException: Cannot load UserDirEnrollment' in result['stderr']
            elif profile == 'caDirUserCert':
                assert 'PKIException: Cannot load UserDirEnrollment' in result['stderr']
            else:
                pytest.xfail("Failed to run pki {}".format(req_file, subject.replace('/', '')))


def test_pki_ca_cert_request_submit_with_renewal(ansible_module):
    """
    :Title: Submit certificate request with renewal.
    :Description: Submit certificate request with renewal
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Create the certificate with 1 min exp time.
        2. Submit the renewal certificate request against that certificate
        3. Approve the certificate.
    :Expectedresults:
        1. Certificate request should get submitted successfully.
        2. Certificate should get issued.
    """
    userid = 'testuser{}'.format(random.randint(1111, 99999))
    profile = 'caAgentFoobar'
    subject = 'UID={},CN={}'.format(userid, userid)
    action = 'approve'
    cert_id = user_op.process_certificate_request(ansible_module, subject=subject,
                                                  profile=profile)
    log.info("Generated certificate with {} profile, Cert ID: {}".format(profile, cert_id))
    if cert_id:
        renew_request = ansible_module.pki(cli='ca-cert-request-submit',
                                           nssdb=constants.NSSDB,
                                           dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                           port=constants.CA_HTTP_PORT,
                                           extra_args='--renewal --serial {} '
                                                      '--profile {}'.format(cert_id, 'caUserCert'))
        for result1 in renew_request.values():
            log.info("Running: {}".format(result1['cmd']))
            if result1['rc'] == 0:
                assert 'Submitted certificate request' in result1['stdout']
                assert 'Request ID:' in result1['stdout']
                assert 'Type: renewal' in result1['stdout']
                assert 'Request Status: pending' in result1['stdout']
                assert 'Operation Result: success' in result1['stdout']

                request_id = re.search('Request ID: [\w]*',
                                       result1['stdout']).group().encode('utf-8')
                request_id = request_id.split(":")[1].strip()
                log.info("Submitted renewal certificate request : {}".format(request_id))
                log.info("Getting request id : {}".format(request_id))
                log.info("Process request with action : {}".format(action))
                new_cert_id = user_op.process_certificate_request(ansible_module,
                                                                  request_id=request_id,
                                                                  action=action)
                log.info("Issued new certificate with the Cert ID: {}".format(new_cert_id))
            else:
                log.error("Failed to submit renewal certificate request.")
                log.info(result1['stderr'])
                pytest.xfail("Failed to submit certificate renew request.")
