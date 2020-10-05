#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Support of SHA256 for SKI - automation
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   Earlier dogtag support SHA1 for SKI digest. Now this is extended
#   to support SHA256.
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Amol Kahat <akahat@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2017 Red Hat, Inc. All rights reserved.
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
import re
import shutil
import sys
import tempfile

import pytest
from OpenSSL.crypto import load_certificate, FILETYPE_PEM
from lxml import etree

from pki.testlib.common import utils

if os.path.isfile('/tmp/test_dir/constants.py'):
    sys.path.append('/tmp/test_dir')
    import constants

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
topology = int(constants.CA_INSTANCE_NAME.split("-")[-2])
userop = utils.UserOperations(nssdb=constants.NSSDB)
ca_ca_cert = 'caCACert'


@pytest.fixture(scope='function', params=['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'])
def create_sha_prof(ansible_module, request):
    """
    Create a new profile based on caUserCert with Subject Key Identifier - 2.5.29.14 Extension.
    """
    sha_algo = request.param
    extension = {
        'critical': {'Syntax': 'string', 'Constraint': 'readonly', 'Description': 'Criticality'},
        'keyid': {'Syntax': 'string', 'Constraint': 'readonly', 'Description': 'Key ID'},
        'messageDigest': {'Syntax': 'string', 'Constraint': 'readonly',
                          'Description': 'Message digest'}}
    params = {'messageDigest': {'value': sha_algo}}
    temp_dir = tempfile.mkdtemp(suffix="_test", prefix='profile_', dir="/tmp/")

    new_profile_name = ca_ca_cert + str(sha_algo)
    new_profile_path = '/tmp/{}.xml'.format(new_profile_name)
    new_profile_local_path = os.path.join(temp_dir, new_profile_name + ".xml")
    ca_ca_cert_xml = os.path.join(temp_dir, ca_ca_cert + '.xml')
    log.info("Getting profile '{}'".format(ca_ca_cert))
    show_profile = ansible_module.pki(cli='ca-profile-show',
                                      port=constants.CA_HTTP_PORT,
                                      nssdb=constants.NSSDB,
                                      dbpassword=constants.CLIENT_DIR_PASSWORD,
                                      certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                      extra_args='{} --output {}'.format(ca_ca_cert,
                                                                         '/tmp/{}.xml'.format(
                                                                             ca_ca_cert)))
    for res in show_profile.values():
        if res['rc'] == 0:
            assert 'Profile "{}"'.format(ca_ca_cert) in res['stdout']
            assert 'Saved profile {} to {}'.format(ca_ca_cert,
                                                   '/tmp/{}.xml'.format(ca_ca_cert)) \
                   in res['stdout']
            log.info("Successfully retrieved profile '{}'.".format(ca_ca_cert))
        else:
            log.info(res['stderr'])
            log.debug(res)
            pytest.xfail("Failed to retrieve the {} profile.".format(ca_ca_cert))

    ansible_module.fetch(src='/tmp/{}.xml'.format(ca_ca_cert), dest=ca_ca_cert_xml,
                         flat=True)

    if os.path.isfile(ca_ca_cert_xml):
        data = open(ca_ca_cert_xml).read()
        new_data = re.sub(ca_ca_cert, new_profile_name, data)
        xml_root = etree.XML(new_data)
        # xml_root = xml_file.getroot()

        # check if the extension is present or not.
        log.info("Configuring xml profile.")
        subject_key_ext = xml_root.xpath("//*[@classId='subjectKeyIdentifierExtDefaultImpl']")
        if subject_key_ext:
            if len(subject_key_ext) > 1:
                pytest.xfail("Failed to modify profile. More than one extensions present")
            else:
                ext = subject_key_ext[0]
                for child in ext.getchildren():
                    if child.tag == 'params' and child.get('name') == 'messageDigest':
                        if child.getchildren():
                            for v in child.getchildren():
                                v.text = sha_algo
        xml_file = etree.tostring(xml_root, pretty_print=True).decode()
        with open(new_profile_local_path, 'w+') as xml:
            xml.write(xml_file)

    log.info("Copying new profile to the server.")
    ansible_module.copy(src=new_profile_local_path, dest=new_profile_path)
    log.info("Adding new profile '{}'".format(new_profile_path))
    add_profile = ansible_module.pki(cli='ca-profile-add',
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DIR_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                     extra_args=new_profile_path)

    for host, result in add_profile.items():
        if result['rc'] == 0:
            assert 'Added profile {}'.format(new_profile_name) in result['stdout']
            log.info("Added new profile '{}'.".format(new_profile_name))
        else:
            log.error("Failed to add new profile '{}'.".format(new_profile_name))
            log.info(result['stderr'])
            log.debug(result)
            pytest.xfail("")
    enable_profile = ansible_module.pki(cli='ca-profile-enable',
                                        nssdb=constants.NSSDB,
                                        dbpassword=constants.CLIENT_DIR_PASSWORD,
                                        port=constants.CA_HTTP_PORT,
                                        certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                        extra_args=new_profile_name)
    for _, res in enable_profile.items():
        if res['rc'] == 0:
            assert 'Enabled profile "{}"'.format(new_profile_name) in res['stdout']
            log.info("Enabled new profile '{}'.".format(new_profile_name))
        else:
            log.info(res['stderr'])
            log.debug(res)
            log.error("Failed to enable new profile '{}'.".format(new_profile_name))
            pytest.xfail("")
    yield [new_profile_name, sha_algo]

    disable_profile = ansible_module.pki(cli='ca-profile-disable',
                                         nssdb=constants.NSSDB,
                                         dbpassword=constants.CLIENT_DIR_PASSWORD,
                                         port=constants.CA_HTTP_PORT,
                                         certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                         extra_args=new_profile_name)
    for _, res in disable_profile.items():
        if res['rc'] == 0:
            assert 'Disabled profile "{}"'.format(new_profile_name) in res['stdout']
            log.info("disabled new profile '{}'.".format(new_profile_name))
        else:
            log.info(res['stderr'])
            log.debug(res)
            log.info("Failed to disable profile '{}'".format(new_profile_name))
            pytest.xfail("Failed to disable profile {}.".format(new_profile_name))

    delete_profile = ansible_module.pki(cli='ca-profile-del',
                                        nssdb=constants.NSSDB,
                                        dbpassword=constants.CLIENT_DIR_PASSWORD,
                                        port=constants.CA_HTTP_PORT,
                                        certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                        extra_args=new_profile_name)
    for _, res in delete_profile.items():
        if res['rc'] == 0:
            assert 'Deleted profile "{}"'.format(new_profile_name) in res['stdout']
            log.info("Removed new profile '{}' from server.".format(new_profile_name))
        else:
            log.info(res['stderr'])
            log.debug(res)
            log.error("Failed to remove new profile '{}' from server.".format(new_profile_name))
            pytest.xfail("")
    log.info("Cleaning up dirs and files.")
    ansible_module.shell('rm -rf /tmp/{}.xml {}'.format(ca_ca_cert, new_profile_path))
    shutil.rmtree(temp_dir)


@pytest.mark.skipif("topology != 2")
def test_pki_SKI_for_SHA(ansible_module, create_sha_prof):
    """
    :id: e1e5bb29-cc00-4010-a7a2-8c4714e152a3

    :Title: SHA256 Hash of Subject Key Identifier Automation of BZ: 1024558

    :Test: SHA256 Hash of Subject Key Identifier Automation of BZ: 1024558

    :Description: This automation test check if Issued certificate have
                  SKI with different SHA algorithms.

    :Requirement: RHCS-REQ: Support SHA256 for the hash of Subject Key Identifier (SKI)

    :CaseComponent: \-

    :Setup: Use the subsystems setup in ansible to run subsystem commands

    :Steps:
            1. Store caUserCert profile to xml.file.
            2. Edit the profile change the name. Add the extension
               'subjectKeyIdentifierExtDefaultImpl' if not present.
            3. Add the profile. Enable it.
            4. Create certificate request with respect to the latest profile, and approve
               the request.
            5. Pretty print the certificate.

    :Expectedresults:
                1. The certificate should have "Identifier: Subject Key Identifier - 2.5.29.14".
                2. It shows different SHA for different SHA algorithms.
    """
    subject = 'CN=CA Signing Certificate,OU={},O={}'.format(constants.CA_INSTANCE_NAME,
                                                            constants.CA_SECURITY_DOMAIN_NAME)

    sha_algos = {'SHA-1': 20,
                 'SHA-256': 32,
                 'SHA-384': 48,
                 'SHA-512': 64}
    log.info("Cerating certificate with new profile.")
    cert_id = userop.process_certificate_request(ansible_module, subject=subject,
                                                 profile=create_sha_prof[0],
                                                 keysize=2048)
    log.info("Created new certificate {}".format(cert_id))
    cert_show = ansible_module.pki(cli='ca-cert-show',
                                   nssdb=constants.NSSDB,
                                   dbpassword=constants.CLIENT_DIR_PASSWORD,
                                   port=constants.CA_HTTP_PORT,
                                   extra_args='{} --output /tmp/{}.pem'.format(cert_id, cert_id))

    for _, result in cert_show.items():
        if result['rc'] == 0:
            ansible_module.fetch(src='/tmp/{}.pem'.format(cert_id),
                                 dest='/tmp/{}.pem'.format(cert_id),
                                 flat=True)
            if os.path.isfile('/tmp/{}.pem'.format(cert_id)):
                output = ansible_module.pki(cli='ca-cert-show',
                                            nssdb=constants.NSSDB,
                                            dbpassword=constants.CLIENT_DIR_PASSWORD,
                                            port=constants.CA_HTTP_PORT,
                                            extra_args='{} --pretty'.format(cert_id))
                for _, res in output.items():
                    if res['rc'] == 0:
                        sha_digest = re.findall("Identifier: [\w].*", res['stdout'], re.M)
                        count = sha_digest.index("Identifier: Subject Key Identifier - 2.5.29.14")

                        pem_data = open('/tmp/{}.pem'.format(cert_id)).read()
                        certificate = load_certificate(FILETYPE_PEM, bytes(pem_data))

                        subject = certificate.get_extension(count)
                        sha_bytes = len(str(subject).split(":"))
                        assert sha_algos[create_sha_prof[1]] == sha_bytes
                        log.info("Successfully created certificate's SKI with {} "
                                 "algo.".format(create_sha_prof[1]))
                    else:
                        log.info(res['stderr'])
                        log.debug(res)
                        log.info("Failed to map {} digest with the "
                                 "certificate".format(create_sha_prof[1]))
                        pytest.xfail("Failed to map {} digest with the "
                                     "certificate.".format(create_sha_prof[1]))
            else:
                log.info(result['stderr'])
                log.debug(result)
                pytest.xfail("File not found.")
        else:
            pytest.xfail("Failed to run ca-cert-show command.")
