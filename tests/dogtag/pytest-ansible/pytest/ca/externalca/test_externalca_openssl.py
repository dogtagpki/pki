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
def test_externalca_openssl_noskid(ansible_module):
    '''
      :Title: Test when SKID is not supplied to externalCA installation.
      :Description: This is test when ski is not enabled for ExternalCA signing certificate
      :Requirement:CA Installation with existing certs-OCSP

      :Type: Functional
      :setup:
      Refer: https://www.dogtagpki.org/wiki/Issuing_CA_Signing_Certificate_with_openssl
      1. Install RootCA which has rootca generated using certutil utility.
      2. Make sure skid is enabled
      3. Test if the externalCA installation went through.

      :steps:
      Refer: https://www.dogtagpki.org/wiki/Issuing_CA_Signing_Certificate_with_openssl
      1. Install RootCA which has rootca generated using openssl utility.
      2. Make sure skid is enabled
      3. Test if the externalCA installation went through.
      4. Make sure SKID is part of signed certificate and exist.

      :expectedresults:
      1. Installation is successful.
      2. ca-user-find command should work.
      3. Certificate generated using externalCA method has all the needed extensions and fields
      4. This is not a right behavior to install a signing certificate without SKI/AKI.
      https://bugzilla.redhat.com/show_bug.cgi?id=1516118 is raised for it.
    '''
    log = logging.getLogger("test_externalca_openssl")
    instance_creation = openssl_externalca()
    verify = ExternalcaVerify()
    instance_creation.generate_cacert(ansible_module)
    log.info("Generate certificate request using pkispawn step 1")
    output = instance_creation.generate_csr(ansible_module)
    log.info(" Checking output : %s", output)
    instance_creation.issue_cert(ansible_module)
    output = instance_creation.install_externalca(ansible_module)
    log.info("LogFile for installation : %s",output)
    log.info("Create the nssdb")
    out = instance_creation.create_nssdb(ansible_module)
    log.info("Run Commands to create nssdb directory: %s", out)
    out = instance_creation.importp12_externalca(ansible_module)
    log.info("Verify the admin certificate import to nssdb :%s", out)
    out = verify.verify_externalca_causers(ansible_module)
    log.info("VERIFICATION :: %s", out)