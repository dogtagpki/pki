#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI CA-PROFILE CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki ca-profile cli commands needs to be tested:
#   pki ca-profile-add
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Pritam Singh <prisingh@redhat.com>
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

from pki.testlib.common.certlib import sys, os, CertSetup, Setup
from pki.testlib.common.exceptions import PkiLibException
from pki.testlib.common.utils import UserOperations, ProfileOperations
import pytest

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

userop = UserOperations(nssdb=constants.NSSDB)
profop = ProfileOperations(nssdb=constants.NSSDB)
log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)

TOPOLOGY = constants.CA_INSTANCE_NAME.split("-")[-2]

if TOPOLOGY == '02':
    instance_name = 'pki-tomcat'
    topology_name = 'topology-02-CA'
else:
    instance_name = constants.CA_INSTANCE_NAME
    topology_name = constants.CA_INSTANCE_NAME
CA_SUBJECT = 'CN=CA Signing Certificate,OU={},O={}'.format \
    (instance_name, constants.CA_SECURITY_DOMAIN_NAME)

cert_setup = CertSetup(nssdb=constants.NSSDB,
                       db_pass=constants.CLIENT_DATABASE_PASSWORD,
                       host=constants.MASTER_HOSTNAME,
                       port=constants.CA_HTTP_PORT,
                       nick="'{}'".format(constants.CA_ADMIN_NICK))


@pytest.mark.parametrize('args', ['--help', 'asdf', ''])
def test_pki_ca_profile_add_help(ansible_module, args):
    """
    :Title: Test pki ca-profile-add  --help command.
    :Description: test pki ca-profile-add --help command
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c
           SECret.123 -n "PKI CA Administrator for Example.Org"
           ca-profile-add --help
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c
        SECret.123 -n "PKI CA Administrator for Example.Org"
        ca-profile-add asdf
        3. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c
        SECret.123 -n "PKI CA Administrator for Example.Org"
        ca-profile-add
    :Expected results:
        1. It should return help message.
        2. It should return file not found exception
        3. It should return no file specified error
    """
    cmd_out = ansible_module.pki(cli="ca-profile-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(args))
    for result in cmd_out.values():
        if args == '--help':
            assert result['rc'] == 0
            assert "usage: ca-profile-add <file> [OPTIONS...]" in result['stdout']
            assert "--debug     Run in debug mode." in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        elif args == 'asdf':
            assert result['rc'] >= 1
            assert 'FileNotFoundException: asdf (No such file or directory)' in \
                   result['stderr']
            log.info("Successfully run : '{}'".format((result['cmd'])))
        elif args == '':
            assert result['rc'] >= 1
            assert "ERROR: No filename specified." in result['stderr']
            log.info("Successfully ran : '{}'".format(result['cmd']))


def test_pki_ca_profile_create_and_add_profile(ansible_module):
    """
    :Title: Test pki ca-profile create and add profile
    :Description: test pki ca-profile-add with creating and add it
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c
           SECret.123 -n "PKI CA Administrator for Example.Org"
           ca-profile-show caUserCert --output caTest.xml
        2. sed -i 's/caUserCert/caTest/g' caTest.xml
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c
        SECret.123 -n "PKI CA Administrator for Example.Org"
        ca-profile-add caTest.xml
    :Expected results:
        1. It should add a new profile
    """
    # Create the profile
    profile_xml_output = '/tmp/caUserCertFooBar1.xml'
    profile_name = 'testcaUserCert1'
    stored = profop.get_profile_to_xml(ansible_module, profile_name='caUserCert',
                                       profile_path=profile_xml_output)
    assert stored
    ansible_module.replace(dest=profile_xml_output, regexp='caUserCert', replace='testcaUserCert1')
    ansible_module.fetch(src=profile_xml_output, dest=profile_xml_output, flat=True)
    # Add new created profile
    cmd_out = ansible_module.pki(cli="ca-profile-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(profile_xml_output))

    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Added profile {}".format(profile_name) in result['stdout']
            assert "Profile ID: {}".format(profile_name) in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.xfail()
    # Find new created profile
    cmd_out = ansible_module.pki(cli="ca-profile-find",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='--size {}'.format('90'))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Profile ID: {}".format(profile_name) in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            log.info("Failed to ran : '{}'".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Enable new added profile
    profop.enable_profile(ansible_module, profile_name)
    # Disable new added profile
    profop.disable_profile(ansible_module, profile_name)
    # Delete the profile
    profop.delete_profile(ansible_module, profile_name)
    ansible_module.command('rm -rf {}'.format(profile_xml_output))
    os.remove(profile_xml_output)


def test_pki_ca_profile_add_with_custom_profile_valid_for_15_days(ansible_module):
    """
    :Title: Test pki ca-profile-add custom profile valid for 15 days
    :Description: Create custom user profile which is valid for
                  15 days with a grace period of 5 days before and after
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Create a xml file containing user inputs, and set constraints
        with validity period of 15 days and grace period of 5 days before and after
        2. Add the xml file using ca-profile-add cli using Admin Cert
        3. Enable the profile using Agent Cert
        4. Enroll the cert using the profile
    :Expected results:
        1. Verify the custom user profile is added successfully
        2. Cert enrolled using the profile has a validity period of 15 days
           with 5 day before/After grace period for renewal
    """
    # Create the profile
    pro_id = "caUserCertFooBar2"
    profile_xml_output = '/tmp/caUserCertFooBar2.xml'
    p_obj = Setup(profile_type='user', profile_id=pro_id)
    profile_param = {'ProfileName': '%s Enrollment Profile' % (pro_id),
                     'notBefore': '5',
                     'notAfter': '5',
                     'ValidFor': '15',
                     'rangeunit': 'day',
                     'MaxValidity': '30'}
    output_list = p_obj.create_profile(profile_param)
    log.info("Successfully created profile '{}'".format(output_list[0]))
    ansible_module.copy(src=output_list[0], dest=profile_xml_output, force=True)
    # Add the profile
    cmd_out = ansible_module.pki(cli="ca-profile-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(profile_xml_output))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Added profile {}".format(pro_id) in result['stdout']
            assert "Profile ID: {}".format(pro_id) in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            log.info("Failed to ran : '{}'".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
    # Enable the profile
    try:
        assert cert_setup.enable_profile(ansible_module, pro_id)
        log.info("Successfully enabled the profile : {}".format(pro_id))
    except PkiLibException as err:
        log.error("Unable to enable profile, failed with error: '{}'".format(err.msg))
        log.error(result['stdout'])
        log.error(result['stderr'])
        pytest.fail()

    # Create Cert request which satifies name pattern
    user = 'testcaUserCert1'
    fullName = 'testcaUserCert1'
    subject = "UID={},CN={}".format(user, fullName)
    try:
        cert_serial = userop.process_certificate_request(ansible_module, subject=subject, profile=pro_id)
        log.info("Successfully created Cert ID: {}".format(cert_serial))
    except PkiLibException as err:
        log.error("Unable to enroll cert : '{}'".format(err.msg))
        log.error(result['stdout'])
        log.error(result['stderr'])
        pytest.fail()
    cert_serial_file = cert_setup.cert_show(ansible_module, cert_serial)[1]
    cert_file = "/tmp/{}.pem".format(cert_serial)
    ansible_module.fetch(src=cert_serial_file, dest=cert_file, flat=True)
    cert_attributes = cert_setup.cert_attributes(cert_file)
    validity = cert_attributes['notAfter_strformat'] - cert_attributes['notBefore_strformat']
    assert '15 days, 0:00:00' == str(validity)
    log.info("Successfully created profile valid for 15 days")
    # Disable new added profile
    profop.disable_profile(ansible_module, pro_id)
    # Delete the profile
    profop.delete_profile(ansible_module, pro_id)
    ansible_module.command('rm -rf {} {}'.format(cert_serial_file, profile_xml_output))
    os.remove(output_list[0])
    os.remove(cert_file)


def test_pki_ca_profile_add_with_key_enc_and_dec_ext(ansible_module):
    """
    :Title: Test pki ca-profile-add which adds key encipher & decipher extensions
    :Description: Create a user profile which adds key encipher and decipher extensions
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Create a xml file containing user inputs,constraints and Enable
           keyUsage Extensions KeyEncipher and Decipher
        2. Add the xml file using ca-profile-add cli using Admin Cert
        3. Enable the profile using Agent Cert
        4. Enroll the cert using the profile
    :Expected results:
        1. Verify the custom user profile is added successfully
        2. and profile can be be used to enroll certs
    """
    # Create the profile
    profile_xml_output = '/tmp/caUserCertFooBar3.xml'
    pro_id = "caUserCertFooBar3"
    p_obj = Setup(profile_type='user', profile_id=pro_id)
    profile_params = {'ProfileName': '%s Enrollment Profile' % (pro_id),
                      'KeyUsageExtensions': '''
                       keyUsageCritical,
                       keyUsageDigitalSignature,
                       keyUsageNonRepudiation,
                       keyUsageKeyEncipherment,
                       keyUsageEncipherOnly'''}
    output_list = p_obj.create_profile(profile_params)
    log.info("Successfully created profile : '{}'".format(output_list))
    ansible_module.copy(src=output_list[0], dest=profile_xml_output, force=True)
    # Add the profile
    cmd_out = ansible_module.pki(cli="ca-profile-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(profile_xml_output))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Added profile {}".format(pro_id) in result['stdout']
            assert "Profile ID: {}".format(pro_id) in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            log.error("Failed to ran : '{}'".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Enable the profile
    try:
        assert cert_setup.enable_profile(ansible_module, pro_id)
        log.info("Successfully enabled the profile : {}".format(pro_id))
    except PkiLibException as err:
        log.error("Unable to enable profile, failed with error: '{}'".format(err.msg))
        log.error(result['stdout'])
        log.error(result['stderr'])
        pytest.fail()

    # Create Cert request which satisfies name pattern
    user = 'testcaUserCert2'
    fullName = 'testcaUserCert2'
    subject = "UID={},CN={}".format(user, fullName)
    try:
        cert_serial = userop.process_certificate_request(ansible_module, subject=subject, profile=pro_id)
        log.info("Successfully created Cert ID: {}".format(cert_serial))
    except PkiLibException as err:
        log.error("Unable to enroll cert : '{}'".format(err.msg))
        log.error(result['stdout'])
        log.error(result['stderr'])
        pytest.fail()
    else:
        cert_serial_file = cert_setup.cert_show(ansible_module, cert_serial)[1]
        cert_file = "/tmp/{}.pem".format(cert_serial)
        ansible_module.fetch(src=cert_serial_file, dest=cert_file, flat=True)
        cert_attributes = cert_setup.cert_attributes(cert_file)
        assert 'Digital Signature, Non Repudiation, Key Encipherment, Encipher Only' in \
               cert_attributes['extensions']
        log.info("Successfully Executed profile with keyUsageExtensions")
    # Disable new added profile
    profop.disable_profile(ansible_module, pro_id)
    # Delete the profile
    profop.delete_profile(ansible_module, pro_id)
    ansible_module.command('rm -rf {} {}'.format(cert_serial_file, profile_xml_output))
    os.remove(output_list[0])
    os.remove(cert_file)


@pytest.mark.bugzilla('1854959')
def test_pki_ca_profile_add_with_netscape_extensions(ansible_module):
    """
    :Title: Test pki ca-profile-add which adds Netscape Extensions
    :Description: Create a user profile which adds Netscape Extensions
                  nsCertSSLClient and nsCertEmail
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Create a xml file containing user inputs,constraints and Enable
            Netscape Extensions nsCertSSLClient and nsCertEmail in the profile
        2. Add the xml file using ca-profile-add cli using Admin Cert
        3. Enable the profile using Agent Cert
        4. Enroll the cert using the profile
    :Expected results:
        1. Verify the custom user profile is added successfully
        2. and cert enrolled through the profile contains netscape extensions
           nsCertSSLClient and nsCertEmail
    """
    # Create new profile
    profile_xml_output = '/tmp/caUserCertFooBar4.xml'
    pro_id = "caUserCertFooBar4"
    p_obj = Setup(profile_type='user', profile_id=pro_id)
    profile_params = {'ProfileName': '%s Enrollment Profile' % (pro_id),
                      'NetscapeExtensions': '''
                       nsCertCritical,
                       nsCertSSLClient,
                       nsCertEmail'''}
    output_list = p_obj.create_profile(profile_params)
    log.info("Successfully Created Profile : '{}'".format(output_list))
    ansible_module.copy(src=output_list[0], dest=profile_xml_output, force=True)
    # Add the profile
    cmd_out = ansible_module.pki(cli="ca-profile-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(profile_xml_output))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Added profile {}".format(pro_id) in result['stdout']
            assert "Profile ID: {}".format(pro_id) in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            log.error("Failed to ran : '{}'".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Enable the profile
    try:
        assert cert_setup.enable_profile(ansible_module, pro_id)
        log.info("Successfully enabled the profile : {}".format(pro_id))
    except PkiLibException as err:
        log.error("Unable to enable profile, failed with error: '{}'".format(err.msg))
        log.error(result['stdout'])
        log.error(result['stderr'])
        pytest.fail()

    # Create Cert request which satisfies name pattern
    user = 'testcaUserCert3'
    fullName = 'testcaUserCert3'
    subject = "UID={},CN={}".format(user, fullName)
    try:
        cert_serial = userop.process_certificate_request(ansible_module, subject=subject, profile=pro_id)
        log.info("Successfully created Cert ID: {}".format(cert_serial))
    except PkiLibException as err:
        log.error("Unable to enroll cert : '{}'".format(err.msg))
        log.error(result['stdout'])
        log.error(result['stderr'])
        pytest.fail()
    else:
        cert_serial_file = cert_setup.cert_show(ansible_module, cert_serial)[1]
        cert_file = "/tmp/{}.pem".format(cert_serial)
        ansible_module.fetch(src=cert_serial_file, dest=cert_file, flat=True)
        cert_attributes = cert_setup.cert_attributes(cert_file)
        assert 'SSL Client, S/MIME' in cert_attributes['extensions']
        log.info("Successfully created profile with netscape extensions")
    # Disable new added profile
    profop.disable_profile(ansible_module, pro_id)
    # Delete the profile
    profop.delete_profile(ansible_module, pro_id)
    ansible_module.command('rm -rf {} {}'.format(cert_serial_file, profile_xml_output))
    os.remove(output_list[0])
    os.remove(cert_file)


def test_pki_ca_profile_add_with_subject_name_pattern(ansible_module):
    """
    :Title: Test pki ca-profile-add with subject name pattern
    :Description: Create a user profile with subject Name pattern UID=QAGroup-.*
                  and rejects if pattern doesn't match
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Create a xml file containing user inputs, and add a subject name
            pattern constraint "uid=QAGroup-*"
        2. Add the xml file using ca-profile-add cli using Admin Cert
        3. Enable the profile using Agent Cert
        4. Enroll the cert using the profile
    :Expected results:
        1. Verify the custom user profile is added successfully
        2. and accepts request only if the request contains subject dn uid=QAGroup-*
    """
    # Create the profile
    profile_xml_output = '/tmp/caUserCertFooBar5.xml'
    pro_id = "caUserCertFooBar100"
    p_obj = Setup(profile_type='user', profile_id=pro_id)
    profile_params = {'ProfileName': '%s Enrollment Profile' % (pro_id),
                      'subjectNamePattern': 'UID=QAGroup-.*'}
    output_list = p_obj.create_profile(profile_params)
    log.info("Successfully created profile '{}'".format(output_list))
    ansible_module.copy(src=output_list[0], dest=profile_xml_output, force=True)
    # Add the profile
    cmd_out = ansible_module.pki(cli="ca-profile-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(profile_xml_output))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Added profile {}".format(pro_id) in result['stdout']
            assert "Profile ID: {}".format(pro_id) in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            log.error("Failed to ran : '{}'".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Enable the profile
    try:
        assert cert_setup.enable_profile(ansible_module, pro_id)
        log.info("Successfully enabled the profile : {}".format(pro_id))
    except PkiLibException as err:
        log.error("Unable to enable profile, failed with error: '{}'".format(err.msg))
        pytest.xfail()

    # Create Cert request which satisfies name pattern
    user = 'QAGroup-4'
    fullName = 'QAGroup-4'
    subject = "UID={},CN={}".format(user, fullName)
    try:
        cert_serial = userop.process_certificate_request(ansible_module, subject=subject, profile=pro_id)
        log.info("Successfully created Cert ID: {}".format(cert_serial))
    except PkiLibException as err:
        log.error("Unable to enroll cert : '{}'".format(err.msg))
        log.error(result['stdout'])
        log.error(result['stderr'])
        pytest.fail()
    else:
        cert_data, cert_serial_file = cert_setup.cert_show(ansible_module, cert_serial)
        assert "Serial Number: {}".format(cert_serial) in cert_data
        assert "Subject: {}".format(subject) in cert_data
        assert "Status: VALID" in cert_data
        log.info("Successfully created cert for subject : {}".format(subject))

    # Disable new added profile
    profop.disable_profile(ansible_module, pro_id)
    # Delete the profile
    profop.delete_profile(ansible_module, pro_id)
    ansible_module.command('rm -rf {} {}'.format(cert_serial_file, profile_xml_output))
    os.remove(output_list[0])


def test_pki_ca_profile_add_with_custom_subjectdn(ansible_module):
    """
    :Title: Test pki ca-profile-add with custom subjectdn
    :Description: Create a user profile with dc=cracker,dc=org added to
                  Subject DN by default
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Create a xml file containing user input, constraints adding
            dc=cracker,dc=org to the subject DN
        2. Add the xml file using ca-profile-add cli using Admin Cert
        3. Enable the profile using Agent Cert
        4. Enroll the cert using the profile
    :Expected results:
        1. Verify the custom user profile is added successfully
        2. and verify cert contains subject DN contains DC=cracker,DC=org
    """
    # Create the profile
    profile_xml_output = '/tmp/caUserCertFooBar6.xml'
    pro_id = "caServerFooBar1"
    # create a custom profile xml
    p_obj = Setup(profile_type='user', profile_id=pro_id)
    profile_params = {'ProfileName': '%s Enrollment Profile' % (pro_id),
                      'subjectNamePattern': 'CN=[^,]+,.+',
                      'subjectNameDefault': 'CN=$request.req_subject_name.cn$,DC=cracker,DC=org'}

    output_list = p_obj.create_profile(profile_params)
    log.info("Successfully created profile : '{}'".format(output_list))
    ansible_module.copy(src=output_list[0], dest=profile_xml_output, force=True)

    # Add the profile
    cmd_out = ansible_module.pki(cli="ca-profile-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(profile_xml_output))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Added profile {}".format(pro_id) in result['stdout']
            assert "Profile ID: {}".format(pro_id) in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            log.error("Failed to ran '{}'".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Enable the profile
    try:
        assert cert_setup.enable_profile(ansible_module, pro_id)
        log.info("Successfully enabled the profile : {}".format(pro_id))
    except PkiLibException as err:
        log.error("Unable to enable profile, failed with error: '{}'".format(err.msg))
        log.error(result['stdout'])
        log.error(result['stderr'])
        pytest.fail()

    # Create Cert request which satisfies name pattern
    user = 'FooBar1'
    fullName = 'Foobar1'
    subject = "UID={},CN={}".format(user, fullName)
    try:
        cert_serial = userop.process_certificate_request(ansible_module, subject=subject, profile=pro_id)
        log.info("Successfully created Cert ID: {}".format(cert_serial))
    except PkiLibException as err:
        log.error("Unable to enroll cert '{}'".format(err.msg))
        log.error(result['stdout'])
        log.error(result['stderr'])
        pytest.fail()
    else:
        cert_serial_file = cert_setup.cert_show(ansible_module, cert_serial)[1]
        cert_file = "/tmp/{}.pem".format(cert_serial)
        ansible_module.fetch(src=cert_serial_file, dest=cert_file, flat=True)
        cert_attributes = cert_setup.cert_attributes(cert_file)
        if cert_attributes >= 1:
            assert ('DC', 'cracker') in cert_attributes['subject']
            assert ('DC', 'org') in cert_attributes['subject']
            log.info("Successfully created profile with custom subject dn")
        else:
            log.error("Failed to create profile with custom subject dn")
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
    # Disable new added profile
    profop.disable_profile(ansible_module, pro_id)
    # Delete the profile
    profop.delete_profile(ansible_module, pro_id)
    ansible_module.command('rm -rf {} {}'.format(cert_serial_file, profile_xml_output))
    os.remove(output_list[0])
    os.remove(cert_file)


def test_pki_ca_profile_add_with_crl_extension(ansible_module):
    """
    :Title: Test pki ca-profile-add with crl extension
    :Description: Create a user profile which adds CRL extension
                  with URL https://pki.example.org/fullCRL

    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Create a xml file containing user inputs, and add Extension
            containing CRL URL https://pki1.example.com/fullCRL
        2. Add the xml file using ca-profile-add cli using Admin Cert
        3. Enable the profile using Agent Cert
        4. Enroll the cert using the profile
    :Expected results:
        1. Verify the custom user profile is added successfully
        2. and certs enrolled through the profile contains Extension containing
           CRL url https://pki.example.org/fullCRL
    """
    # Create the profile
    profile_xml_output = '/tmp/caUserCertFooBar7.xml'
    pro_id = "caUserCertFooBar6"
    # create a custom profile xml
    p_obj = Setup(profile_type='user', profile_id=pro_id)
    profile_params = {'ProfileName': '%s Enrollment Profile' % (pro_id),
                      'CrlExtensions': 'https://{}/fullCRL'.format(constants.MASTER_HOSTNAME)}
    output_list = p_obj.create_profile(profile_params)
    log.info("Successfully created profile '{}'".format(output_list))
    ansible_module.copy(src=output_list[0], dest=profile_xml_output, force=True)

    # Add the profile
    cmd_out = ansible_module.pki(cli="ca-profile-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(profile_xml_output))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Added profile {}".format(pro_id) in result['stdout']
            assert "Profile ID: {}".format(pro_id) in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            log.error("Failed to ran : '{}'".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Enable the profile
    try:
        assert cert_setup.enable_profile(ansible_module, pro_id)
        log.info("Successfully enabled the profile : {}".format(pro_id))
    except PkiLibException as err:
        log.error("Unable to enable profile, failed with error: '{}'".format(err.msg))
        log.error(result['stdout'])
        log.error(result['stderr'])
        pytest.fail()

    # Create Cert request which satisfies name pattern
    user = 'testcaUserCert4'
    fullName = 'testcaUserCert4'
    subject = "UID={},CN={}".format(user, fullName)
    try:
        cert_serial = userop.process_certificate_request(ansible_module, subject=subject, profile=pro_id)
        log.info("Successfully created Cert ID: {}".format(cert_serial))
    except PkiLibException as err:
        log.error("Unable to enroll cert '{}'".format(err.msg))
        log.error(result['stdout'])
        log.error(result['stderr'])
        pytest.fail()
    else:
        cert_serial_file = cert_setup.cert_show(ansible_module, cert_serial)[1]
        cert_file = "/tmp/{}.pem".format(cert_serial)
        ansible_module.fetch(src=cert_serial_file, dest=cert_file, flat=True)
        cert_attributes = cert_setup.cert_attributes(cert_file)
        if cert_attributes >= 1:
            assert '\nFull Name:\n  URI:https://{}/fullCRL\n'.format(constants.MASTER_HOSTNAME) in \
                   cert_attributes['extensions']
            log.info("Successfully created profile with crl extensions")
        else:
            log.error('CRL Extension was not added to certificate')
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
    # Disable new added profile
    profop.disable_profile(ansible_module, pro_id)
    # Delete the profile
    profop.delete_profile(ansible_module, pro_id)
    ansible_module.command('rm -rf {} {}'.format(cert_serial_file, profile_xml_output))
    os.remove(output_list[0])
    os.remove(cert_file)


def test_pki_ca_profile_add_with_smime_profile(ansible_module):
    """
    :Title: Test pki ca-profile-add with smime profile
    :Description: Create a smime profile xml and add the profile
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Create a xml file containing user inputs, constraints for a smime cert
        2. Add the xml file using ca-profile-add cli using Admin Cert
        3. Enable the profile using Agent Cert
        4. Enroll the cert using the profile
    :Expected results:
        1. Verify the custom smime profile is added successfully
        2. and profile contains smime extensions in the cert enrolled
    """
    # Create the profile
    profile_xml_output = '/tmp/caUserCertFooBar8.xml'
    pro_id = "caUserCertFooBar7"
    # create a custom profile xml
    p_obj = Setup(profile_type='smime', profile_id=pro_id)
    profile_params = {'ProfileName': '%s Enrollment Profile' % (pro_id)}
    output_list = p_obj.create_profile(profile_params)
    log.info("Successfully created profile '{}'".format(output_list))
    ansible_module.copy(src=output_list[0], dest=profile_xml_output, force=True)

    # Add the profile
    cmd_out = ansible_module.pki(cli="ca-profile-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(profile_xml_output))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Added profile {}".format(pro_id) in result['stdout']
            assert "Profile ID: {}".format(pro_id) in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            log.error("Failed to ran '{}'".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Enable the profile
    try:
        assert cert_setup.enable_profile(ansible_module, pro_id)
        log.info("Successfully enabled the profile : {}".format(pro_id))
    except PkiLibException as err:
        pytest.xfail("Unable to enable profile, failed with error: '{}'".format(err.msg))
    user = 'testcaUserCert5'
    fullName = 'testcaUserCert5'
    email = 'testcaUserCert5@example.org'
    subject = "UID={},E={},CN={}".format(user, email, fullName)
    try:
        cert_serial = userop.process_certificate_request(ansible_module, subject=subject, profile=pro_id)
        log.info("Successfully created Cert ID: {}".format(cert_serial))
    except PkiLibException as err:
        log.error("Unable to enroll cert : '{}'".format(err.msg))
        log.error(result['stdout'])
        log.error(result['stderr'])
        pytest.fail()
    else:
        cert_data, cert_serial_file = cert_setup.cert_show(ansible_module, cert_serial)
        assert "Serial Number: {}".format(cert_serial) in cert_data
        assert "Subject: {}".format(subject) in cert_data
        assert "Status: VALID" in cert_data
        log.info("Successfully created smime profile")
    # Disable new added profile
    profop.disable_profile(ansible_module, pro_id)
    # Delete the profile
    profop.delete_profile(ansible_module, pro_id)
    ansible_module.command('rm -rf {} {}'.format(cert_serial_file, profile_xml_output))
    os.remove(output_list[0])


def test_pki_ca_profile_add_server_profile(ansible_module):
    """
    :Title: Test pki ca-profile-add server profile
    :Description: Create a server profile xml and add the profile
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Create a xml file containing user inputs, constraints for a server cert
        2. Add the xml file using ca-profile-add cli using Admin Cert
        3. Enable the profile using Agent Cert
        4. Enroll the cert using the profile
    :Expected results:
        1. Verify the custom server profile is added successfully
        2. and certs can be enrolled using the profile
    """
    # Create the profile
    profile_xml_output = '/tmp/caUserCertFooBar9.xml'
    pro_id = "caServerFooBar2"
    # create a custom profile xml
    p_obj = Setup(profile_type='server', profile_id=pro_id)
    profile_params = {'ProfileName': '%s Enrollment Profile' % (pro_id)}
    output_list = p_obj.create_profile(profile_params)
    log.info("Successfully created profile '{}'".format(output_list))
    ansible_module.copy(src=output_list[0], dest=profile_xml_output, force=True)

    # Add the profile
    cmd_out = ansible_module.pki(cli="ca-profile-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(profile_xml_output))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Added profile {}".format(pro_id) in result['stdout']
            assert "Profile ID: {}".format(pro_id) in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            log.error("Failed to ran : '{}'".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Enable the profile
    try:
        assert cert_setup.enable_profile(ansible_module, pro_id)
        log.info("Successfully enabled the profile : {}".format(pro_id))
    except PkiLibException as err:
        log.error("Unable to enable profile, failed with error: '{}'".format(err.msg))
        log.error(result['stdout'])
        log.error(result['stderr'])
        pytest.fail()

    # Create a certificate request
    cn = 'testcaServerCert1'
    ou = 'IDMQE'
    subject = "CN={},OU={}".format(cn, ou)
    try:
        cert_serial = userop.process_certificate_request(ansible_module, subject=subject, profile=pro_id)
        log.info("Successfully created Cert ID: {}".format(cert_serial))
    except PkiLibException as err:
        log.error("Unable to enroll cert : '{}'".format(err.msg))
        log.error(result['stdout'])
        log.error(result['stderr'])
        pytest.fail()
    else:
        cert_serial_file = cert_setup.cert_show(ansible_module, cert_serial)[1]
        cert_file = "/tmp/{}.pem".format(cert_serial)
        ansible_module.fetch(src=cert_serial_file, dest=cert_file, flat=True)
        cert_attributes = cert_setup.cert_attributes(cert_file)
        if cert_attributes >= 1:
            assert 'TLS Web Client Authentication, E-mail Protection' in \
                   cert_attributes['extensions']
            log.info("Successfully created server profile")
        else:
            log.error("TLS Web Client Authentication extension not found in cert")
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
    # Disable new added profile
    profop.disable_profile(ansible_module, pro_id)
    # Delete the profile
    profop.delete_profile(ansible_module, pro_id)
    ansible_module.command('rm -rf {} {}'.format(cert_serial_file, profile_xml_output))
    os.remove(output_list[0])
    os.remove(cert_file)


def test_pki_ca_profile_add_server_profile_with_subjectnamepattern(ansible_module):
    """
    :Title: Test pki ca-profile-add server profile with subject name pattern
    :Description: Create a custom server profile which rejects request
                  if subject DN doesn't have *.otherexample.org
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Create a xml file containing user inputs, constraints for a server cert
        2. Add the xml file using ca-profile-add cli using Admin Cert
        3. Enable the profile using Agent Cert
        4. Enroll the cert using the profile
    :Expected results:
        1. Verify the custom server profile is added successfully
        2. and certs can be enrolled using the profile
    """
    # Create the profile
    profile_xml_output = '/tmp/caUserCertFooBar10.xml'
    pro_id = "caServerFooBar3"
    # create a custom profile xml
    p_obj = Setup(profile_type='server', profile_id=pro_id)
    profile_params = {'ProfileName': '%s Enrollment Profile' % (pro_id),
                      'subjectNamePattern': 'CN=.*.otherexample.org.*'}
    output_list = p_obj.create_profile(profile_params)
    log.info("Successfully created profile '{}'".format(output_list))
    ansible_module.copy(src=output_list[0], dest=profile_xml_output, force=True)

    # Add the profile
    cmd_out = ansible_module.pki(cli="ca-profile-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(profile_xml_output))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Added profile {}".format(pro_id) in result['stdout']
            assert "Profile ID: {}".format(pro_id) in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            log.error("Failed to ran '{}'".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Enable the profile
    try:
        assert cert_setup.enable_profile(ansible_module, pro_id)
        log.info("Successfully enabled the profile : {}".format(pro_id))
    except PkiLibException as err:
        log.error("Unable to enable profile, failed with error: '{}'".format(err.msg))
        log.error(result['stdout'])
        log.error(result['stderr'])
        pytest.fail()

    # Create a certificate request
    cn = 'testcaServerCert2.otherexample.org'
    ou = 'IDMQE'
    subject = "CN={},OU={}".format(cn, ou)
    try:
        cert_serial = userop.process_certificate_request(ansible_module, subject=subject, profile=pro_id)
        log.info("Successfully created Cert ID: {}".format(cert_serial))
    except PkiLibException as err:
        log.error("Unable to enroll cert '{}'".format(err.msg))
        log.error(result['stdout'])
        log.error(result['stderr'])
        pytest.fail()
    else:
        cert_data, cert_serial_file = cert_setup.cert_show(ansible_module, cert_serial)
        assert "Serial Number: {}".format(cert_serial) in cert_data
        assert "Subject: {}".format(subject) in cert_data
        assert "Status: VALID" in cert_data
        log.info("Successfully created cert for subject : {}".format(subject))

    # Disable new added profile
    profop.disable_profile(ansible_module, pro_id)
    # Delete the profile
    profop.delete_profile(ansible_module, pro_id)
    ansible_module.command('rm -rf {} {}'.format(cert_serial_file, profile_xml_output))
    os.remove(output_list[0])


def test_pki_ca_profile_profile_add_server_profile_with_netscape_extensions(ansible_module):
    """
    :Title: Test pki ca-profile-add server profile with netscape extension
    :Description: Create a server profile which adds Netscape Extensions
                  nsCertSSlClient and nsCertEmail
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Create a xml file containing user inputs,constraints and Enable
            Netscape Extensions nsCertSSLClient and nsCertEmail in the profile
        2. Add the xml file using ca-profile-add cli using Admin Cert
        3. Enable the profile using Agent Cert
        4. Enroll the cert using the profile
    :Expected results:
        1. Verify the custom server profile is added successfully
        2. and cert enrolled through the profile contains netscape extensions
           nsCertSSLClient and nsCertEmail
    """
    # Create the profile
    profile_xml_output = '/tmp/caUserCertFooBar11.xml'
    pro_id = "caServerFooBar4"
    p_obj = Setup(profile_type='server', profile_id=pro_id)
    profile_params = {'ProfileName': '%s Enrollment Profile' % (pro_id),
                      'NetscapeExtensions': '''
                       nsCertCritical,
                       nsCertSSLClient,
                       nsCertEmail'''}
    output_list = p_obj.create_profile(profile_params)
    log.info("Successfully Created Profile '{}'".format(output_list))
    ansible_module.copy(src=output_list[0], dest=profile_xml_output, force=True)

    # Add the profile
    cmd_out = ansible_module.pki(cli="ca-profile-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(profile_xml_output))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Added profile {}".format(pro_id) in result['stdout']
            assert "Profile ID: {}".format(pro_id) in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            log.error("Failed to ran '{}'".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Enable the profile
    try:
        assert cert_setup.enable_profile(ansible_module, pro_id)
        log.info("Successfully enabled the profile : {}".format(pro_id))
    except PkiLibException as err:
        log.error("Unable to enable profile, failed with error: '{}'".format(err.msg))
        log.error(result['stdout'])
        log.error(result['stderr'])
        pytest.fail()

    # Create Cert request which satisfies name pattern
    cn = 'testcaServer3'
    ou = 'IDMQE'
    subject = "CN={},OU={}".format(cn, ou)
    try:
        cert_serial = userop.process_certificate_request(ansible_module, subject=subject, profile=pro_id)
        log.info("Successfully created Cert ID: {}".format(cert_serial))
    except PkiLibException as err:
        log.error("Unable to enroll cert : '{}'".format(err.msg))
        log.error(result['stdout'])
        log.error(result['stderr'])
        pytest.fail()
    else:
        cert_serial_file = cert_setup.cert_show(ansible_module, cert_serial)[1]
        cert_file = "/tmp/{}.pem".format(cert_serial)
        ansible_module.fetch(src=cert_serial_file, dest=cert_file, flat=True)
        cert_attributes = cert_setup.cert_attributes(cert_file)
        assert 'SSL Client, S/MIME' in cert_attributes['extensions']
        log.info("Successfully created server profile with netscape extension")
    # Disable new added profile
    profop.disable_profile(ansible_module, pro_id)
    # Delete the profile
    profop.delete_profile(ansible_module, pro_id)
    ansible_module.command('rm -rf {} {}'.format(cert_serial_file, profile_xml_output))
    os.remove(output_list[0])
    os.remove(cert_file)


def test_pki_ca_profile_add_server_prof_with_custom_subjectdn(ansible_module):
    """
    :Title: Test pki ca-profile-add server profile with custom subject dn
    :Description: Create a server profile with subject Name pattern having
                  CN=[^,]+,.+ and adding dc=example,dc=org by default to
                  subject DN
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Create a xml file containing user inputs, constraints adding
           pattern "dc=example,dc=org" to the subject dn
        2. Add the xml file using ca-profile-add cli using Admin Cert
        3. Enable the profile using Agent Cert
        4. Enroll the cert using the profile

    :Expected results:
        1. Verify the custom server profile is added successfully
        2. and certs can be enrolled using the profile
    """
    # Create the profile
    profile_xml_output = '/tmp/caUserCertFooBar12.xml'
    pro_id = "caServerFooBar5"
    # create a custom profile xml
    p_obj = Setup(profile_type='server', profile_id=pro_id)
    profile_params = {'ProfileName': '%s Enrollment Profile' % (pro_id),
                      'subjectNameDefault': 'CN=$request.req_subject_name.cn$,DC=example,DC=org'}

    output_list = p_obj.create_profile(profile_params)
    log.info("Successfully created profile '{}'".format(output_list))
    ansible_module.copy(src=output_list[0], dest=profile_xml_output, force=True)

    # Add the profile
    cmd_out = ansible_module.pki(cli="ca-profile-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(profile_xml_output))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Added profile {}".format(pro_id) in result['stdout']
            assert "Profile ID: {}".format(pro_id) in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            log.error("Failed to ran '{}'".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Enable the profile
    try:
        assert cert_setup.enable_profile(ansible_module, pro_id)
        log.info("Successfully enabled the profile : {}".format(pro_id))
    except PkiLibException as err:
        log.error("Unable to enable profile, failed with error: '{}'".format(err.msg))
        log.error(result['stdout'])
        log.error(result['stderr'])
        pytest.fail()

    # Create Cert request which satisfies name pattern
    cn = 'testcaServer4'
    ou = 'IDMQE'
    subject = "CN={},OU={}".format(cn, ou)
    try:
        cert_serial = userop.process_certificate_request(ansible_module, subject=subject, profile=pro_id)
        log.info("Successfully created Cert ID: {}".format(cert_serial))
    except PkiLibException as err:
        log.error("Unable to enroll cert '{}'".format(err.msg))
        log.error(result['stdout'])
        log.error(result['stderr'])
        pytest.fail()
    else:
        cert_serial_file = cert_setup.cert_show(ansible_module, cert_serial)[1]
        cert_file = "/tmp/{}.pem".format(cert_serial)
        ansible_module.fetch(src=cert_serial_file, dest=cert_file, flat=True)
        cert_attributes = cert_setup.cert_attributes(cert_file)
        if cert_attributes >= 1:
            assert ('DC', 'example') in cert_attributes['subject']
            assert ('DC', 'org') in cert_attributes['subject']
            log.info("Successfully created server profile with custom subject dn")
        else:
            log.error("DC=example,DC=org not found in subject")
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
    # Disable new added profile
    profop.disable_profile(ansible_module, pro_id)
    # Delete the profile
    profop.delete_profile(ansible_module, pro_id)
    ansible_module.command('rm -rf {} {}'.format(cert_serial_file, profile_xml_output))
    os.remove(output_list[0])
    os.remove(cert_file)


def test_pki_ca_profile_add_server_prof_with_key_enc_and_dec_ext(ansible_module):
    """
    :Title: Test pki ca-profile-add server profile with key encipher & decipher extensions
    :Description: Create a server profile which adds key Encipher and decipher extensions
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Create a server profile containing user inputs,constraints and Enable
           keyUsage Extensions KeyEncipher and Decipher
        2. Add the xml file using ca-profile-add cli using Admin Cert
        3. Enable the profile using Agent Cert
        4. Enroll the cert using the profile
    :Expected results:
        1. Verify the custom server profile is added successfully
        2. and profile can be be used to enroll certs
    """
    # Create the profile
    profile_xml_output = '/tmp/caUserCertFooBar13.xml'
    pro_id = "caServerFooBar6"
    p_obj = Setup(profile_type='server', profile_id=pro_id)
    profile_params = {'ProfileName': '%s Enrollment Profile' % (pro_id),
                      'KeyUsageExtensions': '''
                       keyUsageCritical,
                       keyUsageDigitalSignature,
                       keyUsageNonRepudiation,
                       keyUsageKeyEncipherment,
                       keyUsageEncipherOnly'''}
    output_list = p_obj.create_profile(profile_params)
    log.info("Successfully created profile '{}'".format(output_list))
    ansible_module.copy(src=output_list[0], dest=profile_xml_output, force=True)

    # Add the profile
    cmd_out = ansible_module.pki(cli="ca-profile-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(profile_xml_output))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Added profile {}".format(pro_id) in result['stdout']
            assert "Profile ID: {}".format(pro_id) in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            log.error("Failed to ran '{}'".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Enable the profile
    try:
        assert cert_setup.enable_profile(ansible_module, pro_id)
        log.info("Successfully enabled the profile : {}".format(pro_id))
    except PkiLibException as err:
        log.error("Unable to enable profile, failed with error: '{}'".format(err.msg))
        log.error(result['stdout'])
        log.error(result['stderr'])
        pytest.fail()

    # Create Cert request which satisfies name pattern
    cn = 'testcaServer5'
    ou = 'IDMQE'
    subject = "CN={},OU={}".format(cn, ou)
    try:
        cert_serial = userop.process_certificate_request(ansible_module, subject=subject, profile=pro_id)
        log.info("Successfully created Cert ID: {}".format(cert_serial))
    except PkiLibException as err:
        log.error("Unable to enroll cert '{}'".format(err.msg))
    else:
        cert_serial_file = cert_setup.cert_show(ansible_module, cert_serial)[1]
        cert_file = "/tmp/{}.pem".format(cert_serial)
        ansible_module.fetch(src=cert_serial_file, dest=cert_file, flat=True)
        cert_attributes = cert_setup.cert_attributes(cert_file)
        if cert_attributes >= 1:
            assert 'Digital Signature, Non Repudiation, Key Encipherment, Encipher Only' in \
                   cert_attributes['extensions']
            log.info("Successfully created server profile with keyusageextensions")
        else:
            log.error("Key Encipherment and Encipher Only extensions not found in cert")
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
    # Disable new added profile
    profop.disable_profile(ansible_module, pro_id)
    # Delete the profile
    profop.delete_profile(ansible_module, pro_id)
    ansible_module.command('rm -rf {} {}'.format(cert_serial_file, profile_xml_output))
    os.remove(output_list[0])
    os.remove(cert_file)


def test_pki_ca_profile_add_server_profile_with_crl_extension(ansible_module):
    """
    :Title: Test pki ca-profile-add server profile with crl extension
    :Description: Create a server profile which adds CRL extension
                  with URL https://pki1.example.com/fullCRL
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Create a xml file accepting server CSR, Add constraints
            with regard to CRL extension containing CRL URL https://pki.example.org/fullCRL
        2. Add the xml file using ca-profile-add cli using Admin Cert
        3. Enable the profile using Agent Cert
        4. Enroll the cert using the profile
    :Expected results:
        1. Verify the custom server profile is added successfully and certs
           can be enrolled using the profile
    """
    # Create the profile
    profile_xml_output = '/tmp/caUserCertFooBar14.xml'
    pro_id = "caServerFooBar7"
    # create a custom profile xml
    p_obj = Setup(profile_type='server', profile_id=pro_id)
    profile_params = {'ProfileName': '%s Enrollment Profile' % (pro_id),
                      'CrlExtensions': 'https://{}/fullCRL'.format(constants.MASTER_HOSTNAME)}
    output_list = p_obj.create_profile(profile_params)
    log.info("Successfully created profile '{}'".format(output_list))
    ansible_module.copy(src=output_list[0], dest=profile_xml_output, force=True)

    # Add the profile
    cmd_out = ansible_module.pki(cli="ca-profile-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(profile_xml_output))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Added profile {}".format(pro_id) in result['stdout']
            assert "Profile ID: {}".format(pro_id) in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            log.error("Failed to ran '{}'".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Enable the profile
    try:
        assert cert_setup.enable_profile(ansible_module, pro_id)
        log.info("Successfully enabled the profile : {}".format(pro_id))
    except PkiLibException as err:
        log.error("Unable to enable profile, failed with error: '{}'".format(err.msg))
        log.error(result['stdout'])
        log.error(result['stderr'])
        pytest.fail()

    # Create Cert request which satisfies name pattern
    cn = 'testcaServer6'
    ou = 'IDMQE'
    subject = "CN={},OU={}".format(cn, ou)
    try:
        cert_serial = userop.process_certificate_request(ansible_module, subject=subject, profile=pro_id)
        log.info("Successfully created Cert ID: {}".format(cert_serial))
    except PkiLibException as err:
        log.error("Unable to enroll cert '{}'".format(err.msg))
        log.error(result['stdout'])
        log.error(result['stderr'])
        pytest.fail()
    else:
        cert_serial_file = cert_setup.cert_show(ansible_module, cert_serial)[1]
        cert_file = "/tmp/{}.pem".format(cert_serial)
        ansible_module.fetch(src=cert_serial_file, dest=cert_file, flat=True)
        cert_attributes = cert_setup.cert_attributes(cert_file)
        if cert_attributes >= 1:
            assert '\nFull Name:\n  URI:https://{}/fullCRL\n'.format(constants.MASTER_HOSTNAME) in \
                   cert_attributes['extensions']
            log.info("Successfully created server profile with crl extensions")
        else:
            log.error('CRL Extension was not added to certificate')
    # Disable new added profile
    profop.disable_profile(ansible_module, pro_id)
    # Delete the profile
    profop.delete_profile(ansible_module, pro_id)
    ansible_module.command('rm -rf {} {}'.format(cert_serial_file, profile_xml_output))
    os.remove(output_list[0])
    os.remove(cert_file)


def test_pki_ca_profile_add_server_profile_with_dns_in_subjectaltname(ansible_module):
    """
    :Title: Test pki ca-profile-add server profile with dns in subjectaltname
    :Description: Create a server profile which SubjectAlt Name Extension
                  having DNSName foobar.example.org
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Create a xml file accepting server CSR, Add SAN extension
           containing DNS foobar.example.org
        2. Add the xml file using ca-profile-add cli using Admin Cert
        3. Enable the profile using Agent Cert
        4. Enroll the cert using the profile
    :Expected results:
        1. Verify the custom server profile is added successfully
        2. and verify certs enrolled using the profile contains SAN extension
    """
    # Create the profile
    profile_xml_output = '/tmp/caUserCertFooBar15.xml'
    pro_id = "caFooBar8"
    # create a custom profile xml
    p_obj = Setup(profile_type='server', profile_id=pro_id)
    profile_params = {'ProfileName': '%s Enrollment Profile' % (pro_id),
                      'altType': 'DNSName',
                      'altPattern': 'foobar.example.org'}
    output_list = p_obj.create_profile(profile_params)
    log.info("Successfully created profile '{}'".format(output_list))
    ansible_module.copy(src=output_list[0], dest=profile_xml_output, force=True)

    # Add the profile
    cmd_out = ansible_module.pki(cli="ca-profile-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(profile_xml_output))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Added profile {}".format(pro_id) in result['stdout']
            assert "Profile ID: {}".format(pro_id) in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            log.error("Failed to ran '{}'".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Enable the profile
    try:
        assert cert_setup.enable_profile(ansible_module, pro_id)
        log.info("Successfully enabled the profile : {}".format(pro_id))
    except PkiLibException as err:
        log.error("Unable to enable profile, failed with error: '{}'".format(err.msg))
        log.error(result['stdout'])
        log.error(result['stderr'])
        pytest.fail()

    # Create Cert request which satisfies name pattern
    cn = 'testca7'
    ou = 'IDMQE'
    subject = "CN={},OU={}".format(cn, ou)
    try:
        cert_serial = userop.process_certificate_request(ansible_module, subject=subject, profile=pro_id)
        log.info("Successfully created Cert ID: {}".format(cert_serial))
    except PkiLibException as err:
        log.error("Unable to enroll cert '{}'".format(err.msg))
        log.error(result['stdout'])
        log.error(result['stderr'])
        pytest.fail()
    else:
        cert_serial_file = cert_setup.cert_show(ansible_module, cert_serial)[1]
        cert_file = "/tmp/{}.pem".format(cert_serial)
        ansible_module.fetch(src=cert_serial_file, dest=cert_file, flat=True)
        cert_attributes = cert_setup.cert_attributes(cert_file)
        if cert_attributes >= 1:
            assert 'DNS:foobar.example.org' in cert_attributes['extensions']
            log.info("Successfully created server profile with subject altname extension")
        else:
            log.error('Subject AltName Extension was not added to cert')
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
    # Disable new added profile
    profop.disable_profile(ansible_module, pro_id)
    # Delete the profile
    profop.delete_profile(ansible_module, pro_id)
    ansible_module.command('rm -rf {} {}'.format(cert_serial_file, profile_xml_output))
    os.remove(output_list[0])
    os.remove(cert_file)


def test_ca_profile_add_netscape_extensions_to_ca_cert(ansible_module):
    """
    :Title: Test pki ca-profile-add with netscape extensions
    :Description: Create a CA profile which adds Netscape Extenions to CA Certificate
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Create a xml file accepting CSR, Adds Netscape Extensions nsCertSSLCA,
        nsCertSSLCA, too KeyUsage  extensions
        2. Add the xml file using ca-profile-add cli using Admin Cert
        3. Enable the profile using Agent Cert
        4. Enroll the cert using the profile
    :Expected results:
        1. Verify the custom CA profile is added
        2. and Certificate generated using the profile contains
           Netscape Extensions nsCertSSLCA,nsCertEmailCA
    """
    # Create the profile
    profile_xml_output = '/tmp/caUserCertFooBar16.xml'
    pro_id = "caFooBar9"
    # create a custom profile xml
    p_obj = Setup(profile_type='ca', profile_id=pro_id)
    profile_params = {'ProfileName': '%s Enrollment Profile' % (pro_id),
                      'NetscapeExtensions': '''
                       nsCertCritical,
                       nsCertSSLCA,
                       nsCertEmailCA'''}
    output_list = p_obj.create_profile(profile_params)
    log.info("Successfully created profile '{}'".format(output_list))
    ansible_module.copy(src=output_list[0], dest=profile_xml_output, force=True)

    # Add the profile
    cmd_out = ansible_module.pki(cli="ca-profile-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(profile_xml_output))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Added profile {}".format(pro_id) in result['stdout']
            assert "Profile ID: {}".format(pro_id) in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            log.error("Failed to ran '{}'".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Enable the profile
    try:
        assert cert_setup.enable_profile(ansible_module, pro_id)
        log.info("Successfully enabled the profile : {}".format(pro_id))
    except PkiLibException as err:
        log.error("Unable to enable profile, failed with error: '{}'".format(err.msg))
        log.error(result['stdout'])
        log.error(result['stderr'])
        pytest.fail()

    # Create Cert request which satisfies name pattern
    cn = 'testca8'
    ou = 'IDMQE'
    subject = "CN={},OU={}".format(cn, ou)
    try:
        cert_serial = userop.process_certificate_request(ansible_module, subject=subject, profile=pro_id)
        log.info("Successfully created Cert ID: {}".format(cert_serial))
    except PkiLibException as err:
        log.error("Unable to enroll cert '{}'".format(err.msg))
        log.error(result['stdout'])
        log.error(result['stderr'])
        pytest.fail()
    else:
        cert_serial_file = cert_setup.cert_show(ansible_module, cert_serial)[1]
        cert_file = "/tmp/{}.pem".format(cert_serial)
        ansible_module.fetch(src=cert_serial_file, dest=cert_file, flat=True)
        cert_attributes = cert_setup.cert_attributes(cert_file)
        if cert_attributes >= 1:
            assert 'S/MIME, SSL CA, S/MIME CA' in cert_attributes['extensions']
            log.info("Successfully created ca profile with netscape extensions")
        else:
            log.error("Netscape SSL CA Extenions was not added to profile")
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
    # Disable new added profile
    profop.disable_profile(ansible_module, pro_id)
    # Delete the profile
    profop.delete_profile(ansible_module, pro_id)
    ansible_module.command('rm -rf {} {}'.format(cert_serial_file, profile_xml_output))
    os.remove(output_list[0])
    os.remove(cert_file)


def test_pki_ca_profile_add_crl_extension_to_ca_cert(ansible_module):
    """
    :Title: Test pki ca-profile-add with crl extension
    :Description: Create a CA profile which adds CRL distribution point to
                  Extended key usage extensions
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Create a xml file accepting server CSR, Add constraints
            with regard to CRL extension containing CRL URL https://pki.example.org/fullCRL
        2. Add the xml file using ca-profile-add cli using Admin Cert
        3. Enable the profile using Agent Cert
        4. Enroll the cert using the profile
    :Expected results:
        1. Verify the custom CA profile is added and Certificate generated
           using the profile contains CRL distribution point
    """
    # Create the profile
    profile_xml_output = '/tmp/caUserCertFooBar17.xml'
    pro_id = "caFooBar10"
    # create a custom profile xml
    p_obj = Setup(profile_type='ca', profile_id=pro_id)
    profile_params = {'ProfileName': '%s Enrollment Profile' % (pro_id),
                      'CrlExtensions': 'https://{}/fullCRL'.format(constants.MASTER_HOSTNAME)}
    output_list = p_obj.create_profile(profile_params)
    log.info("Successfully created profile '{}'".format(output_list))
    ansible_module.copy(src=output_list[0], dest=profile_xml_output, force=True)

    # Add the profile
    cmd_out = ansible_module.pki(cli="ca-profile-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(profile_xml_output))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Added profile {}".format(pro_id) in result['stdout']
            assert "Profile ID: {}".format(pro_id) in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            log.error("Failed to ran '{}'".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Enable the profile
    try:
        assert cert_setup.enable_profile(ansible_module, pro_id)
        log.info("Successfully enabled the profile : {}".format(pro_id))
    except PkiLibException as err:
        log.error("Unable to enable profile, failed with error: '{}'".format(err.msg))
        log.error(result['stdout'])
        log.error(result['stderr'])
        pytest.fail()

    # Create Cert request which satisfies name pattern
    cn = 'testca10'
    ou = 'IDMQE'
    subject = "CN={},OU={}".format(cn, ou)
    try:
        cert_serial = userop.process_certificate_request(ansible_module, subject=subject, profile=pro_id)
        log.info("Successfully created Cert ID: {}".format(cert_serial))
    except PkiLibException as err:
        log.error("Unable to enroll cert '{}'".format(err.msg))
        log.error(result['stdout'])
        log.error(result['stderr'])
        pytest.fail()
    else:
        cert_serial_file = cert_setup.cert_show(ansible_module, cert_serial)[1]
        cert_file = "/tmp/{}.pem".format(cert_serial)
        ansible_module.fetch(src=cert_serial_file, dest=cert_file, flat=True)
        cert_attributes = cert_setup.cert_attributes(cert_file)
        if cert_attributes >= 1:
            assert '\nFull Name:\n  URI:https://{}/fullCRL\n'.format(constants.MASTER_HOSTNAME) in \
                   cert_attributes['extensions']
            log.info("Successfully created ca profile with crl extensions")
        else:
            log.error('CRL Extension was not added to certificate')
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
    # Disable new added profile
    profop.disable_profile(ansible_module, pro_id)
    # Delete the profile
    profop.delete_profile(ansible_module, pro_id)
    ansible_module.command('rm -rf {} {}'.format(cert_serial_file, profile_xml_output))
    os.remove(output_list[0])
    os.remove(cert_file)


@pytest.mark.parametrize("nick", ["CA_AdminV", "CA_AgentV", "CA_AuditV"])
def test_pki_ca_profile_add_with_valid_user_cert(ansible_module, nick):
    """
    :Title: pki ca-profile-add with different valid user's cert
    :Description: Executing pki ca-profile-add using valid user cert should pass
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Create a xml file containing user inputs, constraints for a user cert
           Add the xml file using ca-profile-add cli using Admin, Agent & Audit valid cert
    :Expected results:
        1. Verify the custom user profile is added successfully
        2. Verify the custom user profile is not added using Agent cert
        3. Verify the custom user profile is not added using Auditor cert
    """
    # Create the profile
    profile_xml_output = '/tmp/caUserCertFooBar18.xml'
    pro_id = "caUserFooBar1"

    # create a custom profile xml
    p_obj = Setup(profile_type='user', profile_id=pro_id)
    profile_params = {'ProfileName': '%s Enrollment Profile' % (pro_id)}
    output_list = p_obj.create_profile(profile_params)
    log.info("Successfully created profile '{}'".format(output_list))
    ansible_module.copy(src=output_list[0], dest=profile_xml_output, force=True)

    # Add the profile
    cmd_out = ansible_module.pki(cli="ca-profile-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(nick),
                                 extra_args='{}'.format(profile_xml_output))
    for result in cmd_out.values():
        if nick == 'CA_AdminV':
            if result['rc'] == 0:
                assert "Added profile {}".format(pro_id) in result['stdout']
                assert "Profile ID: {}".format(pro_id) in result['stdout']
                log.info("Successfully ran : {}".format(result['cmd']))
            else:
                log.error("Failed to ran '{}'".format(result['cmd']))
                pytest.xfail()
        elif nick in ['CA_AgentV', 'CA_AuditV']:
            if result['rc'] >= 1:
                assert "ForbiddenException: Authorization Error" in result['stderr']
            else:
                log.error("Failed to ran '{}'".format(result['cmd']))
                log.error(result['stdout'])
                log.error(result['stderr'])
                pytest.fail()
    # Delete the profile
    profop.delete_profile(ansible_module, pro_id)
    ansible_module.command('rm -rf {}'.format(profile_xml_output))


@pytest.mark.parametrize("nick", ["CA_AdminR", "CA_AgentR", "CA_AuditR"])
def test_pki_ca_profile_add_with_revoked_user_cert(nick, ansible_module):
    """
    :Title: pki ca-profile-add with different revoked user's cert
    :Description: Executing pki ca-profile-add using revoked user cert
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Create a xml file containing user inputs, constraints for a user cert
           Add the xml file using ca-profile-add cli using Admin, Agent & Audit revoked cert
    :Expected results:
        1. Verify the custom user profile is not added with revoked certs

    """
    # Create the profile
    profile_xml_output = '/tmp/caUserCertFooBar19.xml'
    pro_id = "caUserFooBar2"

    # create a custom profile xml
    p_obj = Setup(profile_type='user', profile_id=pro_id)
    profile_params = {'ProfileName': '%s Enrollment Profile' % (pro_id)}
    output_list = p_obj.create_profile(profile_params)
    log.info("Successfully created profile '{}'".format(output_list))
    ansible_module.copy(src=output_list[0], dest=profile_xml_output, force=True)

    # Add the profile
    cmd_out = ansible_module.pki(cli="ca-profile-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(nick),
                                 extra_args='{}'.format(profile_xml_output))
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert "PKIException: Unauthorized" in result['stderr']
            log.info("Successfully ran '{}'".format(result['cmd']))
        else:
            log.error("Failed to ran '{}'".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
    # Delete the profile
    profop.delete_profile(ansible_module, pro_id)
    ansible_module.command('rm -rf {}'.format(profile_xml_output))


@pytest.mark.parametrize("nick", ["CA_AdminE", "CA_AgentE", "CA_AuditE"])
def test_pki_ca_profile_add_with_expired_user_cert(nick, ansible_module):
    """
    :Title: pki ca-profile-add with different user's expired cert
    :Description: Executing pki ca-profile-add using expired user cert
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Create a xml file containing user inputs, constraints for a user cert
           Add the xml file using ca-profile-add cli using Admin, Agent & Audit expired cert
    :Expected results:
        1. Verify the custom user profile is not added with expired certs

    """
    # Create the profile
    profile_xml_output = '/tmp/caUserCertFooBar20.xml'
    pro_id = "caUserFooBar3"

    # create a custom profile xml
    p_obj = Setup(profile_type='user', profile_id=pro_id)
    profile_params = {'ProfileName': '%s Enrollment Profile' % (pro_id)}
    output_list = p_obj.create_profile(profile_params)
    log.info("Successfully created profile '{}'".format(output_list))
    ansible_module.copy(src=output_list[0], dest=profile_xml_output, force=True)

    # Add the profile
    cmd_out = ansible_module.pki(cli="ca-profile-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(nick),
                                 extra_args='{}'.format(profile_xml_output))
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert "SEVERE: FATAL: SSL alert received: CERTIFICATE_EXPIRED\nIOException: " \
                   "SocketException cannot read on socket: Error reading from socket: " \
                   "(-12269) SSL peer rejected your certificate as expired." in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
    # Delete the profile
    profop.delete_profile(ansible_module, pro_id)
    ansible_module.command('rm -rf {}'.format(profile_xml_output))


def test_pki_ca_profile_add_with_invalid_user(ansible_module):
    """
    :Title: pki ca-profile-add with invalid user's cert
    :Description: Issue pki ca-profile-add with invalid user
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c SECret.123
           -u pki_user -w Secret123 ca-profile-add caTest.xml
    :Expected results:
        1. It should return an Unauthorised Exception.

    """
    # Create the profile
    profile_xml_output = '/tmp/caUserCertFooBar21.xml'
    pro_id = "caUserFooBar4"

    # create a custom profile xml
    p_obj = Setup(profile_type='user', profile_id=pro_id)
    profile_params = {'ProfileName': '%s Enrollment Profile' % (pro_id)}
    output_list = p_obj.create_profile(profile_params)
    log.info("Successfully created profile '{}'".format(output_list))
    ansible_module.copy(src=output_list[0], dest=profile_xml_output, force=True)

    command_out = ansible_module.pki(cli="ca-profile-add",
                                     nssdb=constants.NSSDB,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     authType='basicAuth',
                                     hostname=constants.MASTER_HOSTNAME,
                                     username='"{}"'.format("pki_user"),
                                     userpassword='"{}"'.format("Secret123"),
                                     extra_args='{}'.format(profile_xml_output))
    for result in command_out.values():
        if result['rc'] >= 1:
            assert 'PKIException: Unauthorized' in result['stderr']
            log.info('Successfully ran : {}'.format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
    # Delete the profile
    profop.delete_profile(ansible_module, pro_id)
    ansible_module.command('rm -rf {}'.format(profile_xml_output))


def test_pki_ca_profile_add_with_normal_user_cert(ansible_module):
    """
    :Title: pki ca-profile-add with normal user cert
    :Description: Issue pki ca-profile-add with normal user cert should fail
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Add User
        2. Generate User Cert
        3. Add Cert to User
        4. Add User cert in database
        5. Add profile using the same user cert
    :Expected results:
        1. It should return an Forbidden Exception.
    """
    user = 'caUsertest'
    fullName = 'caUsertest'
    subject = "UID={},CN={}".format(user, fullName)
    userop.add_user(ansible_module, 'add', userid=user, user_name=fullName)
    cert_id = userop.process_certificate_request(ansible_module,
                                                 subject=subject,
                                                 request_type='pkcs10',
                                                 algo='rsa',
                                                 keysize='2048',
                                                 profile='caUserCert')
    ansible_module.pki(cli='ca-user-cert-add',
                       nssdb=constants.NSSDB,
                       dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                       port=constants.CA_HTTP_PORT,
                       hostname=constants.MASTER_HOSTNAME,
                       certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                       extra_args='{} --serial {}'.format(user, cert_id))

    cert_import = 'pki -d {} -c {} -P http -p {} -h {} client-cert-import "{}" ' \
                  '--serial {}'.format(constants.NSSDB,
                                       constants.CLIENT_DIR_PASSWORD,
                                       constants.CA_HTTP_PORT,
                                       constants.MASTER_HOSTNAME, user,
                                       cert_id)
    ansible_module.command(cert_import)

    # Create the profile
    profile_xml_output = '/tmp/caUserCertFooBar22.xml'
    pro_id = "caUserFooBar5"

    # create a custom profile xml
    p_obj = Setup(profile_type='user', profile_id=pro_id)
    profile_params = {'ProfileName': '%s Enrollment Profile' % (pro_id)}
    output_list = p_obj.create_profile(profile_params)
    log.info("Successfully created profile '{}'".format(output_list))
    ansible_module.copy(src=output_list[0], dest=profile_xml_output, force=True)

    cmd_out = ansible_module.pki(cli="ca-profile-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTP_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(user),
                                 extra_args='{}'.format(profile_xml_output))
    for result in cmd_out.values():
        if result['rc'] >= 1:
            assert "Forbidden" in result['stderr']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            log.error("Failed to ran : '{}'".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
    # Delete the profile
    profop.delete_profile(ansible_module, pro_id)
    ansible_module.command('rm -rf {}'.format(profile_xml_output))

    # Remove the cert from nssdb
    userop.remove_client_cert(ansible_module, user, subsystem='ca')

    # Remove the user
    userop.remove_user(ansible_module, user, subsystem='ca')


def test_pki_ca_profile_create_and_add_profile_with_i18n_character(ansible_module):
    """
    :id: 3cb8f3c8-f943-4f74-b9b1-665a0564dfed
    :Title: Test pki ca-profile create and add profile with i18n character
    :Description: test pki ca-profile-add with creating and add it with i18n character
    :Requirement:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c
           SECret.123 -n "PKI CA Administrator for Example.Org"
           ca-profile-show caUserCert --output caTest.xml
        2. sed -i 's/caUserCert/ÖrjanÄke/g' caTest.xml
        2. pki -d /opt/pki/certdb -P http -p 20080 -h pki1.example.com -c
        SECret.123 -n "PKI CA Administrator for Example.Org"
        ca-profile-add caTest.xml
    :Expected results:
        1. It should add a new profile
    :Automated: Yes
    """
    # Create the profile
    profile_xml_output = '/tmp/i18n.xml'
    profile_name = 'ÖrjanÄke'
    stored = profop.get_profile_to_xml(ansible_module, profile_name='caUserCert',
                                       profile_path=profile_xml_output)
    assert stored
    ansible_module.replace(dest=profile_xml_output, regexp='caUserCert', replace='ÖrjanÄke')
    ansible_module.fetch(src=profile_xml_output, dest=profile_xml_output, flat=True)
    # Add new created profile
    cmd_out = ansible_module.pki(cli="ca-profile-add",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTPS_PORT,
                                 protocol='https',
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(profile_xml_output))

    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Added profile {}".format(profile_name) in result['stdout'].encode('utf-8')
            assert "Profile ID: {}".format(profile_name) in result['stdout'].encode('utf-8')
            log.info("Successfully ran : '{}'".format(result['cmd'].encode('utf-8')))
        else:
            assert result['rc'] >= 1
            log.info("Failed to ran : '{}'".format(result['cmd'].encode('utf-8')))
            pytest.fail()

    # Find new created profile
    cmd_out = ansible_module.pki(cli="ca-profile-find",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTPS_PORT,
                                 protocol='https',
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='--size {}'.format('90'))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Profile ID: {}".format(profile_name) in result['stdout'].encode('utf-8')
            log.info("Successfully ran : '{}'".format(result['cmd'].encode('utf-8')))
        else:
            assert result['rc'] >= 1
            log.info("Failed to ran : '{}'".format(result['cmd'].encode('utf-8')))
            log.error(result['stdout'].encode('utf-8'))
            log.error(result['stderr'].encode('utf-8'))
            pytest.fail()

    # Enable the profile
    cmd_out = ansible_module.pki(cli="ca-profile-enable",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTPS_PORT,
                                 protocol='https',
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(profile_name))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Enabled profile "{}"'.format(profile_name) in result['stdout'].encode('utf-8')
            log.info("Successfully ran : '{}'".format(result['cmd'].encode('utf-8')))
        else:
            log.error("Failed to run : {}".format(result['cmd'].encode('utf-8')))
            log.error(result['stdout'].encode('utf-8'))
            log.error(result['stderr'].encode('utf-8'))
            pytest.fail()

    # Disable the profile
    cmd_out = ansible_module.pki(cli="ca-profile-disable",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTPS_PORT,
                                 protocol='https',
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(profile_name))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Disabled profile "{}"'.format(profile_name) in result['stdout'].encode('utf-8')
            log.info("Successfully ran : '{}'".format(result['cmd'].encode('utf-8')))
        else:
            log.error("Failed to run : {}".format(result['cmd'].encode('utf-8')))
            log.error(result['stdout'].encode('utf-8'))
            log.error(result['stderr'].encode('utf-8'))
            pytest.fail()

    # Delete the newly created profile
    cmd_out = ansible_module.pki(cli="ca-profile-del",
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 port=constants.CA_HTTPS_PORT,
                                 protocol='https',
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                 extra_args='{}'.format(profile_name))

    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Deleted profile "{}"'.format(profile_name) in result['stdout'].encode('utf-8')
            log.info("Successfully ran : '{}'".format(result['cmd'].encode('utf-8')))
        else:
            log.error("Failed to ran : '{}'".format(result['cmd'].encode('utf-8')))
            log.error(result['stdout'].encode('utf-8'))
            log.error(result['stderr'].encode('utf-8'))
            pytest.fail()
    ansible_module.command('rm -rf {}'.format(profile_xml_output))
    os.remove(profile_xml_output)
