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
import pytest
import sys

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
cmd = 'ca-cert-show'


@pytest.mark.parametrize('subcmd', ('', '--help', 'asdfa'))
def test_pki_cert_show_help(ansible_module, subcmd):
    """
    :Title: Test pki ca-cert-show with '' and --help option
    :Description:
        This test will show the results of ca-cert-show with '' and --help options
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-cert-show ''
        2. Run pki ca-cert-show --help
    :Expectedresults:
        1. It should throw the "Error: Missing Serial Number" error
        2. It should show help messages.
    """
    help_out = ansible_module.pki(cli=cmd,
                                  port=constants.CA_HTTP_PORT,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                  extra_args='{}'.format(subcmd))
    for result in help_out.values():
        if result['rc'] == 0:
            assert 'usage: {} <Serial Number> [OPTIONS...]'.format(cmd) in result['stdout']
            assert '--encoded         Base-64 encoded' in result['stdout']
            assert '--help            Show help options' in result['stdout']
            assert '--output <file>   Output file' in result['stdout']
            assert '--pretty          Pretty print' in result['stdout']
        elif subcmd == 'asdfa':
            assert 'NumberFormatException: For input string: "asdfa"' in result['stderr']
        else:
            assert 'Error: Missing Serial Number.' in result['stderr']


@pytest.mark.parametrize('subcmd', ('0x1', '0x2'))
def test_pki_cert_show_with_valid_hex_no(ansible_module, subcmd):
    """
    :Title: Test pki ca-cert-show with valid hex no.
    :Description:
        It should show the certificate when valid hex serial no is passed to the command.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-cert-show 0x1
        2. Run pki ca-cert-show 0x2
    :Expectedresults:
        1. It should show the certificate 0x1
        2. It should show the certificate 0x2
    """
    show_out = ansible_module.pki(cli=cmd,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  port=constants.CA_HTTP_PORT,
                                  protocol='http',
                                  certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                  extra_args=' {}'.format(subcmd))
    for result in show_out.values():
        if result['rc'] == 0:
            assert 'Certificate "{}"'.format(subcmd) in result['stdout']
            assert 'Serial Number: {}'.format(subcmd) in result['stdout']
            assert 'Issuer DN: ' in result['stdout']
            assert 'Subject DN: ' in result['stdout']
            assert 'Status: VALID' in result['stdout']
            assert 'Not Valid Before: ' in result['stdout']
            assert 'Not Valid After: ' in result['stdout']
        else:
            pytest.xfail("Failed to run pki {} {}".format(cmd, subcmd))


@pytest.mark.parametrize('subcmd', ('1', '2'))
def test_pki_cert_show_with_valid_decimal_no(ansible_module, subcmd):
    """
    :Title: Test pki ca-cert-show with valid decimal no.
    :Description:
        This test will show the certificate of the user when the valid decimal serial no is passed.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-cert-show 1
        2. Run pki ca-cert-show 2
    :Expectedresults:
        1. It should show the certificate which have serial no 1
        2. It should show the certificate which have serial no 2
    """
    show_out = ansible_module.pki(cli=cmd,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  port=constants.CA_HTTP_PORT,
                                  protocol='http',
                                  certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                  extra_args=' {}'.format(subcmd))
    for result in show_out.values():
        if result['rc'] == 0:
            assert 'Certificate "{}"'.format(hex(int(subcmd))) in result['stdout']
            assert 'Serial Number: {}'.format(hex(int(subcmd))) in result['stdout']
            assert 'Issuer DN: ' in result['stdout']
            assert 'Subject DN: ' in result['stdout']
            assert 'Status: VALID' in result['stdout']
            assert 'Not Valid Before: ' in result['stdout']
            assert 'Not Valid After: ' in result['stdout']
        else:
            pytest.xfail("Failed to run pki {} {}".format(cmd, subcmd))


@pytest.mark.parametrize('subcmd', ("8959412", "9659060"))
def test_pki_cert_show_with_invalid_nos(ansible_module, subcmd):
    """
    :Title: Test pki ca-cert-show with invalid nos
    :Description:
        When invalid decimal and hex no is passed to the command then it should throw the error.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-cert-show <invalid_decimal_no>
        2. Run pki ca-cert-show <invalid_hex_no>
    :Expectedresults:
        1. It should throw the Exception : CertNotFoundException
        2. It should throw the Exception : CertNotFoundException
    """
    show_out = ansible_module.pki(cli=cmd,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  protocol='http',
                                  port=constants.CA_HTTP_PORT,
                                  certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                  extra_args=' {}'.format(subcmd))
    for result in show_out.values():
        if result['rc'] == 0:
            assert 'Certificate "{}"'.format(subcmd) in result['stdout']
            assert 'Serial Number: {}'.format(subcmd) in result['stdout']
            assert 'Issuer: ' in result['stdout']
            assert 'Subject: ' in result['stdout']
            assert 'Status: VALID' in result['stdout']
            assert 'Not Before: ' in result['stdout']
            assert 'Not After: ' in result['stdout']
            pytest.xfail("Failed to run pki {} {}".format(cmd, subcmd))
        else:
            assert 'CertNotFoundException: Certificate ID {} ' \
                   'not found'.format(hex(int(subcmd)) if 'x' not in str(subcmd) else subcmd) in \
                   result['stderr']


def test_pki_cert_show_with_invalid_string(ansible_module):
    """
    :Title: Test pki ca-cert-show with invalid string
    :Description:
        This test should throw an error when invalid string is provided to the command.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-cert-show <invalid_string>
    :Expectedresults:
        1. It should throw an NumberFormatException
    """
    show_out = ansible_module.pki(cli=cmd,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  protocol='http',
                                  port=constants.CA_HTTP_PORT,
                                  certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                  extra_args=' {}'.format('sdfsdfwinfs'))
    for result in show_out.values():
        if result['rc'] == 0:
            assert 'Certificate ' in result['stdout']
            assert 'Serial Number:' in result['stdout']
            assert 'Issuer: ' in result['stdout']
            assert 'Subject: ' in result['stdout']
            assert 'Status: VALID' in result['stdout']
            assert 'Not Before: ' in result['stdout']
            assert 'Not After: ' in result['stdout']
            pytest.xfail("Failed to run pki {} ".format(cmd))
        else:
            assert 'NumberFormatException: For input string: "{}"'.format('sd') in \
                    result['stderr']


@pytest.mark.parametrize('serial', ('1', '0x1'))
def test_pki_cert_show_encoded_with_valid_serial_no(ansible_module, serial):
    """
    :Title: Test pki ca-cert-show with --encoded option with hex and decimal serial no.
    :Description:
        This test will show certificate in an encoded format when --encoded option is provided with
        valid decimal and serial no.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-cert-show 1 --encoded
        2. Run pki ca-cert-show 0x1 --encoded
    :Expectedresults:
        1. It should show the certificate in encoded format when decimal serial passed.
        2. It should show the certificate in encoded format when hex serial no passed.
    """
    show_out = ansible_module.pki(cli=cmd,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  port=constants.CA_HTTP_PORT,
                                  protocol='http',
                                  certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                  extra_args=' {} --encoded'.format(serial))
    for result in show_out.values():
        hex_serial = hex(int(serial)) if 'x' not in str(serial) else serial
        if result['rc'] == 0:
            assert 'Certificate "{}"'.format(hex_serial) in result['stdout']
            assert 'Serial Number: {}'.format(hex_serial) in result['stdout']
            assert 'Issuer DN: ' in result['stdout']
            assert 'Subject DN: ' in result['stdout']
            assert 'Status: VALID' in result['stdout']
            assert 'Not Valid Before: ' in result['stdout']
            assert 'Not Valid After: ' in result['stdout']
            assert '-----BEGIN CERTIFICATE-----' in result['stdout']
            assert '-----END CERTIFICATE-----' in result['stdout']
        else:
            pytest.xfail("Faild to run pki {} {} --encoded".format(cmd, hex_serial))


@pytest.mark.parametrize('serial', ('', '0xs231'))
def test_pki_cert_show_encoded_with_invalid_serial_no(ansible_module, serial):
    """
    :Title: Test pki ca-cert-show when nothing or invalid no is passed with --encoded option.
    :Description:
        This test will test pki ca-cert-show with nothing ('') or invalid no is passed when
        --encoded option is provided, as expected it should throw an error with '' missing serial no
        and certificate not found or NumberFormatException with invalid no.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-cert-show '' --encoded option.
        2. Run pki ca-cert-show <invalid_no> --encoded option.
    :Expectedresults:
        1. It should throw "Missing Serial No" exception.
        2. It should throw "NumberFormatException" for invalid no.
    """
    show_out = ansible_module.pki(cli=cmd,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  port=constants.CA_HTTP_PORT,
                                  protocol='http',
                                  certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                  extra_args=' {} --encoded'.format(serial))
    for result in show_out.values():
        if result['rc'] >= 1:
            if serial == '':
                assert 'Error: Missing Serial Number.' in result['stderr']
            else:
                assert "NumberFormatException: For input string: {}".format(serial.split('x')[1])


@pytest.mark.parametrize('serial', ('1', '0x2'))
def test_pki_cert_show_output_with_valid_serial_no(ansible_module, serial):
    """
    :Title: Test pki ca-cert-show with valid serial no and --output option.
    :Description:
        Test pki ca-cert-show with valid serial no and --output option should store certificate
        in file.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-cert-show <valid_decimal_serial_no> --output <file_name>
        2. Run pki ca-cert-show <valid_hex_serial_no> --output <file_name>
    :Expectedresults:
        1. It should create file and certificate should get stored in file.
        2. It should create file and certificate should get stored in file.
    """
    hex_serial = hex(int(serial)) if 'x' not in str(serial) else serial
    show_out = ansible_module.pki(cli=cmd,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  port=constants.CA_HTTP_PORT,
                                  protocol='http',
                                  certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                  extra_args=' {} --output /tmp/{}.pem'.format(serial, hex_serial))
    for _, result in show_out.items():
        if result['rc'] == 0:
            assert 'Certificate "{}"'.format(hex_serial) in result['stdout']
            assert 'Serial Number: {}'.format(hex_serial) in result['stdout']
            assert 'Issuer DN: ' in result['stdout']
            assert 'Subject DN: ' in result['stdout']
            assert 'Status: VALID' in result['stdout']
            assert 'Not Valid Before: ' in result['stdout']
            assert 'Not Valid After: ' in result['stdout']

            file_stat = ansible_module.stat(path='/tmp/{}.pem'.format(hex_serial))
            for result1 in file_stat.values():
                assert result1['stat']['exists'] == True
        else:
            pytest.xfail("Failed to run pki {} --output /tmp/{}.pem".format(cmd, hex_serial))


@pytest.mark.parametrize('serial', ('', '12422', '0xese232323', '23892(3)'))
def test_pki_cert_show_output_with_invalid_serial_no(ansible_module, serial):
    """
    :Title: Test pki ca-cert-show with invalid serial no when --output parameter is passed.
    :Description:
        It should throw an exception for different inputs.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-cert-show '' --output <file_name>
        2. Run pki ca-cert-show 12422 --output <file_name>
        3. Run pki ca-cert-show 0xese232323 --output <file_name>
        4. Run pki ca-cert-show 23892(3) --output <file_name>
    :Expectedresults:
        1. It should throw "Missing Serial no" error.
        2. It should throw "CertNotFoundException".
        3. It should throw "NumberFormatException"
        4. It should throw "NumberFormatException"
    """
    error = ''
    if serial == '':
        error = 'Error: Missing Serial Number.'
    elif serial == '12422':
        error = 'CertNotFoundException: Certificate ID 0x3086 not found'
    elif serial == '0xese232323':
        error = 'NumberFormatException: For input string: "es"'
    elif serial == '23892(3)':
        error = 'NumberFormatException: For input string: "23892(3)"'
    show_out = ansible_module.pki(cli=cmd,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  port=constants.CA_HTTP_PORT,
                                  protocol='http',
                                  certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                  extra_args=' {} --output /tmp/test_1.pem'.format(serial))
    for result in show_out.values():
        if result['rc'] == 0:
            assert 'Certificate "{}"'.format(hex(int(serial))) in result['stdout']
            assert 'Serial Number: {}'.format(hex(int(serial))) in result['stdout']
            assert 'Issuer DN: ' in result['stdout']
            assert 'Subject DN: ' in result['stdout']
            assert 'Status: VALID' in result['stdout']
            assert 'Not Valid Before: ' in result['stdout']
            assert 'Not Valid After: ' in result['stdout']
            pytest.xfail("Failed to run pki {} --output /tmp/test_1.pem".format(cmd))
        else:
            assert error in result['stderr']


@pytest.mark.parametrize('serial', ('1', '2', '3', '4'))
def test_pki_cert_show_pretty_with_valid_serial_no(ansible_module, serial):
    """
    :Title: Test pki ca-cert-show with valid serial no when --pretty option is provided.
    :Description:
        It should print the certificate in pretty print format with valid serial no.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-cert-show 1 --pretty
        2. Run pki ca-cert-show 2 --pretty
        3. Run pki ca-cert-show 3 --pretty
        4. Run pki ca-cert-show 4 --pretty
    :Expectedresults:
        1. It should show certificate in pretty print format
    """
    show_out = ansible_module.pki(cli=cmd,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  port=constants.CA_HTTP_PORT,
                                  protocol='http',
                                  certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                  extra_args=' {} --pretty'.format(serial))
    hex_serial = hex(int(serial)) if 'x' not in str(serial) else serial
    for result in show_out.values():
        assert 'Certificate "{}"'.format(hex_serial) in result['stdout']
        assert 'Serial Number: {}'.format(hex_serial) in result['stdout']
        assert 'Issuer: ' in result['stdout']
        assert 'Subject: ' in result['stdout']
        assert 'Status: VALID' in result['stdout']
        assert 'Not Before: ' in result['stdout']
        assert 'Not  After: ' in result['stdout']
        assert 'Certificate:' in result['stdout']
        assert 'Data:' in result['stdout']
        assert 'Version:  v3' in result['stdout']
        assert 'Serial Number: {}'.format(hex(int(serial))) in result['stdout']
        assert 'Signature Algorithm:' in result['stdout']
        assert 'Subject Public Key Info:' in result['stdout']
        assert 'Algorithm:' in result['stdout']
        assert 'Public Key:' in result['stdout']
        assert 'Exponent:' in result['stdout']
        assert 'Public Key Modulus:' in result['stdout']
        assert 'Extensions:' in result['stdout']
        assert 'Signature:' in result['stdout']
        assert 'FingerPrint' in result['stdout']
        assert 'MD2:' in result['stdout']
        assert 'MD5:' in result['stdout']
        assert 'SHA-1:' in result['stdout']
        assert 'SHA-256:' in result['stdout']
        assert 'SHA-512:' in result['stdout']


@pytest.mark.parametrize('serial', ('', '12422', '0xese232323', '23892(3)'))
def test_pki_cert_show_pretty_with_invalid_serial_no(ansible_module, serial):
    """
    :Title: Test pki ca-cert-show when invalid no is provided with --pretty option.
    :Description:
        Test pki ca-cert-show with --pretty option should throw an exception when invalid nos are
        provided.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystem setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-cert-show '' --petty
        2. Run pki ca-cert-show 12422 --petty
        3. Run pki ca-cert-show 0xese232323 --petty
        4. Run pki ca-cert-show 23892(3) --petty
    :Expectedresults:
        1. It should throw "Missing Serial no" error.
        2. It should throw "CertNotFoundException".
        3. It should throw "NumberFormatException"
        4. It should throw "NumberFormatException"
    """
    error = ''
    if serial == '':
        error = 'Error: Missing Serial Number.'
    elif serial == '12422':
        error = 'CertNotFoundException: Certificate ID 0x3086 not found'
    elif serial == '0xese232323':
        error = 'NumberFormatException: For input string: "es"'
    elif serial == '23892(3)':
        error = 'NumberFormatException: For input string: "23892(3)"'
    show_out = ansible_module.pki(cli=cmd,
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  port=constants.CA_HTTP_PORT,
                                  protocol='http',
                                  certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                  extra_args=' {} --pretty'.format(serial))
    for result in show_out.values():
        if result['rc'] == 0:
            assert 'Certificate "{}"'.format(hex(int(serial))) in result['stdout']
            assert 'Serial Number: {}'.format(hex(int(serial))) in result['stdout']
            assert 'Issuer: ' in result['stdout']
            assert 'Subject: ' in result['stdout']
            assert 'Status: VALID' in result['stdout']
            assert 'Not Before: ' in result['stdout']
            assert 'Not  After: ' in result['stdout']
            pytest.xfail("Failed to run pki {} --output /tmp/test_1.pem".format(cmd))
        else:
            assert error in result['stderr']

# TODO need to add test cases for the users with i18 characters.
# @pytest.mark.parametrize('userid, fullName',(["Örjan_Äke", "Örjan Äke"]))

#  ('Éric_Têko', 'Éric Têko'),
#  ('éénentwintig_dvidešimt', 'éénentwintig dvidešimt'),
#  ('kakskümmend_üks', 'kakskümmend üks'),
#  ('двадцять_один_тридцять', 'двадцять один тридцять'))
# )

# @pytest.mark.parametrize('cmd', ('cert-show', 'ca-cert-show'))
# @pytest.mark.parametrize('port, protocol',([constants.CA_HTTP_PORT, 'http'],
#                                            [constants.CA_HTTPS_PORT, 'https']))
# @pytest.mark.parametrize('user, name',(['Örjan_Äke', 'Örjan Äke'],
#                                        ['Éric_Têko', 'Éric Têko'],
#                                        ['éénentwintig_dvidešimt', 'éénentwintig dvidešimt'],
#                                        ['kakskümmend_üks', 'kakskümmend üks'],
#                                        ['двадцять_один_тридцять', 'двадцять один тридцять']))
# def test_pki_cert_show_with_i18n_characters(ansible_module, cmd, port, protocol, user, name):
#     userid = user
#     fullName = name
#     user_op = utils.UserOperations()
#     user_op.add_user(ansible_module, 'add', userid=userid, user_name=fullName, subsystem='ca')
#     cert_id = user_op.process_certificate_request(ansible_module, subject='CN={},UID={},'
#                                                                 'E={}@example.org,OU=Engineering,'
#                                                                 'O=Example.Org'.format(userid, userid, userid))
#     show_out = ansible_module.pki(cli=cmd,
#                                   nssdb=constants.NSSDB,
#                                   port=port,
#                                   protocol=protocol,
#                                   certnick="'{}'".format(constants.CA_ADMIN_NICK),
#                                   extra_args=' {}'.format(cert_id))
#     for _, result in show_out.items():
#         if result['rc'] == 0:
#             assert 'Certificate "{}"'.format(cert_id) in result['stdout']
#             assert 'Serial Number: {}'.format(cert_id) in result['stdout']
#             assert 'Issuer: ' in result['stdout']
#             assert 'Subject: ' in result['stdout']
#             assert 'Status: VALID' in result['stdout']
#             assert 'Not Before: ' in result['stdout']
#             assert 'Not After: ' in result['stdout']
#         else:
#             pytest.xfail("Failed to run pki {} --output /tmp/test_1.pem".format(cmd))
#     user_op.remove_user(ansible_module, user)
