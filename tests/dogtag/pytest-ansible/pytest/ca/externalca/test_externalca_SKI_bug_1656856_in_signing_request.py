#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Bug 1656856 - Need Method to Include SKI in CA Signing Certificate Request
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   This is the library for ExternalCA sypporting class and Functions.
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Deepak Punia <dpunia@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2020 Red Hat, Inc. All rights reserved.
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
import os
from time import sleep

from fixtures import config_setup
from utils import *

if os.path.isfile('/tmp/test_dir/constants.py'):
    import sys
    sys.path.append('/tmp/test_dir')
    import constants


def instance_status(ansible_module, status=None):
    command = 'systemctl {} pki-tomcatd@{}'.format(status, constants.CA_INSTANCE_NAME)
    out = ansible_module.shell(command)
    for res in out.values():
        assert res['rc'] == 0
    # Added sleep to wait for instance to come up on restart
    sleep(5)


# initializating object for the instanace creation
instance_creation = pki_externalca()
verify = ExternalcaVerify()

@pytest.mark.usefixtures("config_setup")
def test_bug_1656856_include_SKI_in_ca_signing_certificate_request(ansible_module):
    '''
      :Title: Include SKI in CA Signing Certificate Request
      :Description: Bug 1656856 - Need Method to Include SKI in CA Signing Certificate Request
      :Requirement:  RHCS-REQ  CA Installation with existing certs-OCSP
      :Type: Functional
      :steps:
      Refer: https://polarion.engineering.redhat.com/polarion/#/project/CERT/workitem?id=CERT-25416
      1. Install RootCA which has rootca generated using openssl utility.
      2. Make sure skid is enabled pki_req_ski=00D06F00D4D06746FFFFFFFFFFFFFF and
            Generate a csr using CA step 1 installation.(file ca_step1.cfg)
      3. Make changes in caCACert file. add below parameter and restart
            policyset.caCertSet.8.default.class_id=userExtensionDefaultImpl
            policyset.caCertSet.8.default.name=User Supplied Key Usage Extension
            policyset.caCertSet.8.default.params.userExtOID=2.5.29.14
      4. Generate ca_signing.crt & external.crt and by using that
                        Install CA using second step installation.(file ca_step2.cfg)
      5. Make sure SKID is part of signed certificate and exist.

      :expectedresults:
      1. Installation is successful.
      2. ca-user-find command should work.
      3. Certificate generated using externalCA method has all the needed extensions and fields
      4. Steps 2 installation should be successful with generated crt.
      https://bugzilla.redhat.com/show_bug.cgi?id=1656856 is raised for it.
    '''
    profile_path = "/var/lib/pki/{}/ca/profiles/ca/caCACert.cfg".format(constants.CA_INSTANCE_NAME)
    log = logging.getLogger("test_bug_1656856_include_SKI_in_ca_signing_certificate_request")

    #Create the nssdb
    log.info("Create the nssdb")
    out = instance_creation.create_nssdb(ansible_module)
    log.info("Run Commands to create nssdb directory: %s", out)
    out = instance_creation.importp12_externalca(ansible_module, p12file="/opt/{}/ca_admin_cert.p12".
                                                 format(constants.CA_INSTANCE_NAME))

    #Update custom ski value for step1
    ansible_module.lineinfile(path='/tmp/config_step1.cfg', line="pki_req_ski=00D06F00D4D06746FFFFFFFFFFFFFF")
    output = instance_creation.generate_csr(ansible_module)
    log.info("Generate certificate request using pkispawn step 1")
    log.info(" Checking output : %s", output)

    #Validate csr
    output=ansible_module.shell("openssl req -in {} -noout -text".format('/tmp/ca_signing.csr'))
    for result in output.values():
        if result['rc'] == 0:
            assert "00:D0:6F:00:D4:D0:67:46:FF:FF:FF:FF:FF:FF:FF" in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    #Update custom profile which is required to generate csr
    ansible_module.lineinfile(path=profile_path, regexp='policyset.caCertSet.8.default.class_id',
                              line='policyset.caCertSet.8.default.class_id=userExtensionDefaultImpl')
    ansible_module.lineinfile(path=profile_path, regexp='policyset.caCertSet.8.default.name',
                              line='policyset.caCertSet.8.default.name=User Supplied Key Usage Extension')
    ansible_module.lineinfile(path=profile_path, line='policyset.caCertSet.8.default.params.userExtOID=2.5.29.14')
    instance_status(ansible_module,status='restart')

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

    #Verification part
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
