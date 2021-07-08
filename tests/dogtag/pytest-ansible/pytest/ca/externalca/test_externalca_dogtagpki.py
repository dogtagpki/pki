#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: ExternalCA Supporting functions
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   This is the library for ExternalCA sypporting class and Functions.
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Geetika Kapoor <gkapoor@redhat.com>
#           Shalini Khandelwal <skhandel@redhat.com>
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
import pytest

from fixtures import config_setup
from utils import *

if os.path.isfile('/tmp/test_dir/constants.py'):
    import sys
    sys.path.append('/tmp/test_dir')
    import constants

import re
import logging
from pki.testlib.common.utils import UserOperations
import datetime,time

log = logging.getLogger()
date = str(datetime.date.today())

# Variable used by external CA
nssdb = '/opt/pkitest/certdb'
port = '8443'
user = "testUser"
pem_cert = "/tmp/extCA-agent.pem"


@pytest.mark.usefixtures("config_setup")
def test_externalca_dogtagpki(ansible_module):
    '''
      :Title: Test when SKID is supplied to externalCA installation.
      :Description: This is test when ski is not enabled for ExternalCA signing certificate
      :Requirement:CA Installation with existing certs-OCSP

      :Type: Functional
      :setup:
      Refer: https://github.com/dogtagpki/pki/wiki/Issuing-CA-Signing-Certificate-with-PKI-CA
      1. Install RootCA which has rootca generated using dogtagpki utility.
      2. Make sure skid is enabled
      3. Test if the externalCA installation went through.

      :steps:
      Refer: https://github.com/dogtagpki/pki/wiki/Issuing-CA-Signing-Certificate-with-PKI-CA
      1. Install RootCA which has rootca generated using dogtagpki utility.
      2. Make sure skid is enabled
      3. Test if the externalCA installation went through.
      4. Make sure SKID is part of signed certificate and exist.

      :expectedresults:
      1. Installation is successful.
      2. ca-user-find command should work.
      3. Certificate generated using externalCA method has all the needed extensions and fields
    '''
    log = logging.getLogger("test_externalca_dogtagpki")
    instance_creation = pki_externalca()
    verify = ExternalcaVerify()
    log.info("Create the nssdb")
    out = instance_creation.create_nssdb(ansible_module)
    log.info("Run Commands to create nssdb directory: %s", out)
    out = instance_creation.importp12_externalca(ansible_module, p12file="/opt/{}/ca_admin_cert.p12".
                                                 format(constants.CA_INSTANCE_NAME))
    output = instance_creation.generate_csr(ansible_module)
    log.info("Generate certificate request using pkispawn step 1")
    log.info(" Checking output : %s", output)
    output = instance_creation.submit_csr(ansible_module)
    log.info(" Checking output : %s", output)
    output = instance_creation.find(output,"Request ID:")
    log.info("value of request id is : %s" , output)
    output = instance_creation.approve_csr(ansible_module, output)
    log.info(" Approve csr : %s", output)
    cert = instance_creation.find(output,"Certificate ID:")
    log.info("value of certificate id : %s" , cert)
    output = instance_creation.extract_signingcrt(ansible_module)
    root_id = instance_creation.find(output,"Serial Number:")
    log.info("Serial number is %s", root_id)
    output = instance_creation.extract_external_ca_crt(ansible_module, cert_id=root_id, import_nick=instance_creation.rootca_nick, cert_file=instance_creation.rootca_signing_crt)
    log.info(" Verify the return code while generating RootCA : %d",output)
    output = instance_creation.extract_external_ca_crt(ansible_module, cert_id=cert, import_nick=instance_creation.cacert_nick, cert_file=instance_creation.ca_signing_crt)
    log.info("Verify the return code while signing External CA signing certificate: %d", output)
    output = instance_creation.install_externalca(ansible_module)
    log.info("LogFile for installation : %s",output)
    out = instance_creation.importp12_externalca(ansible_module)
    log.info("Verify the admin certificate import to nssdb :%s", out)
    out = verify.verify_externalca_causers(ansible_module)
    log.info("VERIFICATION :: %s", out)
    log.info("Sign a certificate using ExternalCA")
    output = instance_creation.submit_usercsr(ansible_module)
    log.info(" Checking output : %s", output)
    log.info("User's request id is :%s" %(instance_creation.find(output,"Request ID:")))
    output = instance_creation.approve_usercsr(ansible_module,instance_creation.find(output,"Request ID:"))
    log.info(" Approve csr : %s", output)

def test_ExternalCA_extensions_skid(ansible_module):
    '''
      :Title: Test the skid and akid extensions for ExternalCA
      :Description: This is test when ski is not enabled for ExternalCA signing certificate
      :Requirement:CA Installation with existing certs-OCSP
      :Type: Functional
      :setup:
      Refer: https://github.com/dogtagpki/pki/wiki/Issuing-CA-Signing-Certificate-with-PKI-CA
      1. Install RootCA which has rootca generated using dogtagpki utility.
      2. Make sure skid is enabled
      3. Test if the externalCA installation went through.

      :steps:
      Refer: https://github.com/dogtagpki/pki/wiki/Issuing-CA-Signing-Certificate-with-PKI-CA
      1. Install RootCA which has rootca generated using dogtagpki utility.
      2. Make sure skid is enabled
      3. Test if the externalCA installation went through.
      4. Make sure SKID is part of signed certificate and exist.

      :expectedresults:
      1. Installation is successful.
      2. ca-user-find command should work.
      3. Certificate generated using externalCA method has all the needed extensions and fields
    '''
    log = logging.getLogger("test_externalca_dogtagpki")
    instance_creation = pki_externalca()
    verify = ExternalcaVerify()
    log.info("Get the rootca certificate details and see if skid exist")
    rootca_skid = verify.get_skid(ansible_module, instance_creation.rootca_signing_crt)
    log.info("value of SKID for RootCA is : %s" , rootca_skid)
    rootca_akid = verify.get_akid(ansible_module, instance_creation.rootca_signing_crt)
    log.info("value of AKID for RootCA is : %s", rootca_akid)
    log.info("Comparing two AKID and SKID for RootCA")
    assert rootca_skid in rootca_akid,"Failed to match SKID and AKID for RootCA"
    log.info("Get the ExternalCA certificate details and see if skid exist")
    extca_skid = verify.get_skid(ansible_module, instance_creation.ca_signing_crt)
    log.info("value of SKID for ExternalCA is : %s" ,extca_skid )
    extca_akid = verify.get_akid(ansible_module, instance_creation.ca_signing_crt)
    log.info("value of AKID for ExternalCA is : %s", extca_akid)
    assert extca_akid in rootca_skid,'Failed to match SKID and AKID for ExternalCA'
    log.info("Verified: ExternalCA AKID == RootCA SKID")
    assert extca_skid not in extca_akid,'Failed to match SKID and AKID for ExternalCA'
    log.info("Verified: ExternalCA AKID and SKID are different")
    ansible_module.command("rm -ivf /tmp/ca_signing.csr /tmp/external.crt /tmp/ca_signing.crt")


@pytest.mark.usefixtures("config_setup")
def test_bug_1911472_revoke_with_allowExtCASignedAgentCerts(ansible_module):
    """
    :id: 93c030f5-0cb8-4f61-b8c9-f879feb11652
    :Title: Bug 1911472 - Revoke cert using external ca agent cert with default value.
    :Description: Revoke cert using external ca agent cert with parameter of allowExtCASignedAgentCerts.
    :Requirement: RHCS-REQ  CA Installation with existing certs-OCSP
    :CaseComponent: \-
    :Setup:
       1. Install CA and SubCA.
       2. Create certificate on external CA for agent with name extCA-agent.
       3. Create agent on main CA and import extCA-agent certificate.
    :Steps:
       1. Test with default value of ca.allowExtCASignedAgentCerts=false without any changes.
       2. Test with parameter ca.allowExtCASignedAgentCerts=true in CS.cfg parameter
    :ExpectedResults:
       1. It Should failed with error message UnauthorizedException: Request was unauthorized.
       2. Debug logs should show message "client cert not issued by this CA" and "allowExtCASignedAgentCerts false"
       3. With parameter ca.allowExtCASignedAgentCerts=true Debug logs should show message "client cert not issued by this CA" and "allowExtCASignedAgentCerts true"
    :Automated: Yes
    :customerscenario: yes
    """
    # setup external CA by re-using existing function.
    test_externalca_dogtagpki(ansible_module)

    # export agent user cert from external CA
    subcausercert = ansible_module.pki(cli='ca-cert-find',
                                       nssdb=nssdb,
                                       dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                       port=port,
                                       protocol='https',
                                       certnick="'{}'".format('caadmin'),
                                       extra_args="--uid=testusercert")
    for result in subcausercert.values():
        if result['rc'] == 0:
            serial_no = re.findall('Serial Number:.*', result['stdout'])
            serial_no = serial_no[0].split(":")[1].strip()
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.fail()

    ansible_module.pki(cli='ca-cert-show', nssdb=nssdb,
                       dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                       port=port,
                       protocol='https',
                       certnick="'{}'".format('caadmin'),
                       extra_args="{} --output {}".format(serial_no, pem_cert))

    # Create agent on main CA
    userop = UserOperations(nssdb=nssdb)
    userop.add_user(ansible_module, 'add', userid=user, user_name=user, nssdb=nssdb)

    ansible_module.pki(cli='ca-group-member-add', nssdb=nssdb,
                       dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                       port=constants.CA_HTTPS_PORT,
                       protocol='https',
                       certnick="'{}'".format(constants.CA_ADMIN_NICK),
                       extra_args='"Certificate Manager Agents" {}'.format(user))

    cert_add = ansible_module.pki(cli='ca-user-cert-add', nssdb=nssdb,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  port=constants.CA_HTTPS_PORT,
                                  protocol='https',
                                  certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                  extra_args='{} --input {}'.format(user, pem_cert))
    for result in cert_add.values():
        if result['rc'] == 0:
            assert 'Serial Number: {}'.format(serial_no) in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.fail()

    # Import subCA agent certificate to Root CA agent user.
    import_cert = ansible_module.pki(cli='client-cert-import', nssdb=nssdb,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTPS_PORT,
                                     protocol='https',
                                     certnick="'{}'".format("extAgent"),
                                     extra_args='--cert {}'.format(pem_cert))
    for result in import_cert.values():
        if result['rc'] == 0:
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.fail()

    # Create a certificate on main CA which we need to revoke in test scenario
    cert_id = userop.process_certificate_request(ansible_module, subject="uid=testrevokecert", nssdb=nssdb)

    # Test Scenario 1: Test with default value of ca.allowExtCASignedAgentCerts=false without any changes
    revoke_cert = ansible_module.pki(cli='ca-cert-revoke', nssdb=nssdb,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTPS_PORT,
                                     protocol='https',
                                     certnick="'{}'".format("extAgent"),
                                     extra_args='{} --force'.format(cert_id))
    for result in revoke_cert.values():
        if result['rc'] >= 1:
            assert "UnauthorizedException" in result['stderr']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.fail()

    debug_log = ansible_module.command("tail -n 500 /var/log/pki/{}/ca/debug.{}.log".format(constants.CA_INSTANCE_NAME, date))
    for result in debug_log.values():
        if result['rc'] == 0:
            assert "client cert not issued by this CA" in result['stdout']
            assert "allowExtCASignedAgentCerts false" in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.fail()

    # Test Scenario 2: Test with parameter ca.allowExtCASignedAgentCerts=true in CS.cfg parameter
    ansible_module.lineinfile(dest="/var/lib/pki/{}/ca/conf/CS.cfg".format(constants.CA_INSTANCE_NAME),
                              line="ca.allowExtCASignedAgentCerts=true", state="present")

    ansible_module.shell('systemctl restart pki-tomcatd@{}'.format(constants.CA_INSTANCE_NAME))
    time.sleep(10)

    revoke_cert = ansible_module.pki(cli='ca-cert-revoke', nssdb=nssdb,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTPS_PORT,
                                     protocol='https',
                                     certnick="'{}'".format("extAgent"),
                                     extra_args='{} --force'.format(cert_id))
    for result in revoke_cert.values():
        if result['rc'] == 0:
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.fail()

    debug_log = ansible_module.command("tail -n 500 /var/log/pki/{}/ca/debug.{}.log".format(constants.CA_INSTANCE_NAME, date))
    for result in debug_log.values():
        if result['rc'] == 0:
            assert "client cert not issued by this CA" in result['stdout']
            assert "allowExtCASignedAgentCerts true" in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.fail()

    # Cleaning existing data
    ansible_module.command("rm -ivf /tmp/ca_signing.csr /tmp/external.crt /tmp/ca_signing.crt")
