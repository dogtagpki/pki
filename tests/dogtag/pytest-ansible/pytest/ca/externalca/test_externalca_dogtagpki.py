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

@pytest.mark.usefixtures("config_setup")
def test_externalca_dogtagpki(ansible_module):
    '''
      :Title: Test when SKID is supplied to externalCA installation.
      :Description: This is test when ski is not enabled for ExternalCA signing certificate
      :Requirement:CA Installation with existing certs-OCSP

      :Type: Functional
      :setup:
      Refer: http://www.dogtagpki.org/wiki/Issuing_CA_Signing_Certificate_with_PKI_CA
      1. Install RootCA which has rootca generated using dogtagpki utility.
      2. Make sure skid is enabled
      3. Test if the externalCA installation went through.

      :steps:
      Refer: http://www.dogtagpki.org/wiki/Issuing_CA_Signing_Certificate_with_PKI_CA
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
      Refer: http://www.dogtagpki.org/wiki/Issuing_CA_Signing_Certificate_with_PKI_CA
      1. Install RootCA which has rootca generated using dogtagpki utility.
      2. Make sure skid is enabled
      3. Test if the externalCA installation went through.

      :steps:
      Refer: http://www.dogtagpki.org/wiki/Issuing_CA_Signing_Certificate_with_PKI_CA
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
