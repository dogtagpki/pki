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
import pytest

from fixtures import config_setup
from utils import *

if os.path.isfile('/tmp/test_dir/constants.py'):
    import sys
    sys.path.append('/tmp/test_dir')
    import constants

@pytest.mark.usefixtures("config_setup")
def test_externalca_nssdb_ski_01(ansible_module):
    '''
      :Title: Test when ski is enabled from nssdb side while signing certificate.
      :Description:  This is test when ski is enabled from nssdb side while signing certificate.
      :Requirement:CA Installation with existing certs-OCSP

      :Type: Functional
      :setup:
      Refer: https://github.com/dogtagpki/pki/wiki/Issuing-CA-Signing-Certificate-with-NSS
      1. Install RootCA which has rootca generated using certutil utility.
      2. Make sure skid is enabled
      3. Test if the externalCA installation went through.

      :steps:
      Refer: https://github.com/dogtagpki/pki/wiki/Issuing-CA-Signing-Certificate-with-NSS
      1. Install RootCA which has rootca generated using certutil utility.
      2. Make sure skid is enabled
      3. Test if the externalCA installation went through.
      4. Make sure SKID is part of signed certificate and exist.

      :expectedresults:
      1. Installation is successful.
      2. ca-user-find command should work.
      3. Certificate generated using externalCA method has all the needed extensions and fields.
    '''
    log = logging.getLogger("test_externalca_nssdb_ski_01")
    instance_creation = nssdb_externalca()
    verify = ExternalcaVerify()
    log.info("Create the nssdb")
    out = instance_creation.create_nssdb(ansible_module)
    log.info("Run Commands to create nssdb directory: %s", out)
    output = instance_creation.generate_csr(ansible_module)
    log.info("Generate certificate request using pkispawn step 1")
    log.info(" Checking output : %s", output)
    output = instance_creation.create_rootca_nssdb(ansible_module)
    log.info(" Verify the return code while generating RootCA : %d",output)
    output = instance_creation.create_externalca_cert_skid(ansible_module)
    log.info("Verify the return code while signing External CA signing certificate: %d", output)
    output = instance_creation.install_externalca(ansible_module)
    log.info("LogFile for installation : %s",output)
    out = instance_creation.importp12_externalca(ansible_module)
    log.info("Verify the admin certificate import to nssdb :%s", out)
    out = verify.verify_externalca_causers(ansible_module)
    log.info("VERIFICATION :: %s", out)

@pytest.mark.usefixtures("config_setup")
def test_externalca_nssdb_ski_02(ansible_module):
    '''
      :Title: Test when ski is enabled and ExternalCA skid is > skid of RootCA
      :Description:      This is test when ski is enabled from nssdb side while signing certificate
      here ExternalCA skid is > skid of RootCA.
      :Requirement:CA Installation with existing certs-OCSP

      :Type: Functional
      :setup:
      Refer: https://github.com/dogtagpki/pki/wiki/Issuing-CA-Signing-Certificate-with-NSS
      1. Install RootCA which has rootca generated using certutil utility.
      2. Make sure skid is enabled
      3. Test if the externalCA installation went through.

      :steps:
      Refer: https://github.com/dogtagpki/pki/wiki/Issuing-CA-Signing-Certificate-with-NSS
      1. Install RootCA which has rootca generated using certutil utility.
      2. Make sure skid is enabled
      3. Test if the externalCA installation went through.
      4. Make sure SKID is part of signed certificate and exist.

      :expectedresults:
      1. Installation is successful.
      2. ca-user-find command should work.
      3. Certificate generated using externalCA method has all the needed extensions and fields
    '''
    log = logging.getLogger("test_externalca_nssdb_ski_02")
    instance_creation = nssdb_externalca()
    verify = ExternalcaVerify()
    log.info("Create the nssdb")
    out = instance_creation.create_nssdb(ansible_module)
    log.info("Run Commands to create nssdb directory: %s", out)
    output = instance_creation.generate_csr(ansible_module)
    log.info("Generate certificate request using pkispawn step 1")
    log.info(" Checking output : %s", output)
    output = instance_creation.create_rootca_nssdb(ansible_module)
    log.info(" Verify the return code while generating RootCA : %d",output)
    output = instance_creation.create_externalca_cert_skid \
        (ansible_module, ca_skid = '0x110b97b22f78e85e0b3de580a893a6e01dddf2c47896785645342678901')
    log.info("Verify the return code while signing External CA signing certificate: %d", output)
    output = instance_creation.install_externalca(ansible_module)
    log.info("LogFile for installation : %s",output)
    out = instance_creation.importp12_externalca(ansible_module)
    log.info("Verify the admin certificate import to nssdb :%s", out)
    out = verify.verify_externalca_causers(ansible_module)
    log.info("VERIFICATION :: %s", out)

@pytest.mark.xfail(reason="https://bugzilla.redhat.com/show_bug.cgi?id=1518073")
@pytest.mark.usefixtures("config_setup")
def test_externalca_nssdb_ski_03(ansible_module):
    '''
      :Title: Test when ski is enabled and ExternalCA has empty skid value.
      :Description: This is test when ski is enabled from nssdb side while signing certificate.
    Here we are sending empty skid for external CA..
      :Requirement:CA Installation with existing certs-OCSP

      :CaseComponent: \-
      :Type: Functional
      :setup:
      Refer: https://github.com/dogtagpki/pki/wiki/Issuing-CA-Signing-Certificate-with-NSS
      1. Install RootCA which has rootca generated using certutil utility.
      2. Make sure skid is enabled
      3. Test if the externalCA installation went through.

      :steps:
      Refer: https://github.com/dogtagpki/pki/wiki/Issuing-CA-Signing-Certificate-with-NSS
      1. Install RootCA which has rootca generated using certutil utility.
      2. Make sure skid is enabled
      3. Test if the externalCA installation went through.
      4. Make sure SKID is part of signed certificate and exist.

      :expectedresults:
      1. Installation should fail as skid key exist but no value is assigned to it.
    '''

    log = logging.getLogger("test_externalca_nssdb_ski_03")
    instance_creation = nssdb_externalca()
    verify = ExternalcaVerify()
    log.info("Create the nssdb")
    out = instance_creation.create_nssdb(ansible_module)
    log.info("Run Commands to create nssdb directory: %s", out)
    output = instance_creation.generate_csr(ansible_module)
    log.info("Generate certificate request using pkispawn step 1")
    log.info(" Checking output : %s", output)
    output = instance_creation.create_rootca_nssdb(ansible_module)
    log.info(" Verify the return code while generating RootCA : %d",output)
    output = instance_creation.create_externalca_cert_skid(ansible_module, ca_skid = '')
    log.info("Verify the return code while signing External CA signing certificate: %d", output)
    output = instance_creation.install_externalca(ansible_module)
    log.info("LogFile for installation : %s",output)
    out = instance_creation.importp12_externalca(ansible_module)
    log.info("Verify the admin certificate import to nssdb :%s", out)
    out = verify.verify_externalca_causers(ansible_module)
    log.info("VERIFICATION :: %s", out)