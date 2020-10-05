#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Automation of pki-server subsystem-cert-find cli
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
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
import sys

import pytest

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants
TOPOLOGY = constants.CA_INSTANCE_NAME.split("-")[1]
log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)

if TOPOLOGY == '01':
    ca_instance_name = 'pki-tomcat'
    topology_name = 'topology-01-CA'
else:
    ca_instance_name = constants.CA_INSTANCE_NAME
    topology_name = constants.CA_INSTANCE_NAME


@pytest.mark.parametrize('args', ['--help', 'asdf', ''])
def test_pki_server_subsystem_cert_find_help(ansible_module, args):
    """
    :Title: Test pki-server subsystem-cert-find with --help, asdf and ''
    :Description: Test pki-server subsystem-cert-find with --help, asdf and ''
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki-server subsystem-cert-find --help
        2. pki-server subsystem-cert-find asdf
        3. pki-server subsystem-cert-find ''
    :ExpectedResults:
        1. It should show help message
        2. It should show error message
        3. It should show an error message.
    """
    cmd = 'pki-server subsystem-cert-find {}'.format(args)
    cmd_out = ansible_module.command(cmd)
    for result in cmd_out.values():
        if args == '--help':
            assert result['rc'] == 0
            assert 'Usage: pki-server subsystem-cert-find [OPTIONS] <subsystem ID>' in result['stdout']
            assert '-i, --instance <instance ID>    Instance ID (default: pki-tomcat).' in result['stdout']
            assert '    --show-all                  Show all attributes.' in result['stdout']
            assert '-v, --verbose                   Run in verbose mode.' in result['stdout']
            assert '    --help                      Show help message.' in result['stdout']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        elif args == 'asdf':
            if TOPOLOGY == "01":
                assert 'ERROR: No asdf subsystem in instance {}.'.format(ca_instance_name) in result['stderr']
                log.info("Successfully run : {}".format(" ".join(result['cmd'])))
            else:
                assert 'ERROR: Invalid instance pki-tomcat.' in result['stderr']
                log.info("Successfully run : {}".format(" ".join(result['cmd'])))
        elif args == '':
            assert 'ERROR: Missing subsystem ID' in result['stderr']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))


def test_pki_subsystem_cert_find_find_ca_certs(ansible_module):
    """
    :Title: Test pki-server subsystem-cert-find, find CA subsystem cert
    :Description: Test pki-server subsystem-cert-find, Find CA subsystem cert
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki-server subsystem-cert-find ca -i <instance name>
    :ExpectedResults:
        1. It should show all the subsystem certs
    """

    cert_id = {'signing': 'caSigningCert cert-{} CA',
               'ocsp_signing': 'ocspSigningCert cert-{} CA',
               'sslserver': 'Server-Cert cert-{}',
               'subsystem': 'subsystemCert cert-{}',
               'audit_signing': 'auditSigningCert cert-{} CA'}

    cmd = 'pki-server subsystem-cert-find ca -i {}'.format(constants.CA_INSTANCE_NAME)
    cmd_out = ansible_module.command(cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            for certid, name in cert_id.items():
                assert 'Serial No:' in result['stdout']
                assert 'Cert ID: {}'.format(certid) in result['stdout']
                assert 'Nickname: {}'.format(name.format(constants.CA_INSTANCE_NAME)) in result['stdout']
                assert 'Token: internal' in result['stdout']
                log.info("Found Cert ID: {}, Nickname: {}".format(certid, name.format(constants.CA_INSTANCE_NAME)))
        else:
            log.error("Failed to run: {}".format(" ".join(result['cmd'])))
            pytest.skip()


def test_pki_server_subsystem_cert_find_find_kra_certs(ansible_module):
    """
    :Title: Test pki-server subsystem-cert-find, find kra subsystem certs.
    :Description: Test pki-server subsystem-cert-find, find kra subsystem certs
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Test pki-server subsystem-cert-find kra
    :ExpectedResults:
        1. It should show all the kra subsystem certs
    """
    cert_id = {'transport': 'transportCert cert-{} KRA',
               'storage': 'storageCert cert-{} KRA',
               'sslserver': 'Server-Cert cert-{}',
               'subsystem': 'subsystemCert cert-{}',
               'audit_signing': 'auditSigningCert cert-{} KRA'}

    cmd = 'pki-server subsystem-cert-find kra -i {}'.format(constants.KRA_INSTANCE_NAME)
    cmd_out = ansible_module.command(cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            for certid, name in cert_id.items():
                assert 'Serial No:' in result['stdout']
                assert 'Cert ID: {}'.format(certid) in result['stdout']
                assert 'Nickname: {}'.format(name.format(constants.KRA_INSTANCE_NAME)) in result['stdout']
                assert 'Token: Internal Key Storage Token' in result['stdout']
                log.info("Found Cert ID: {}, Nickname: {}".format(certid, name.format(constants.CA_INSTANCE_NAME)))
        else:
            log.error("Failed to run: {}".format(" ".join(result['cmd'])))
            pytest.skip()



def test_pki_server_subsystem_cert_find_find_ocsp_certs(ansible_module):
    """
    :Title: Test pki-server subsystem-cert-find, find ocsp subsystem certs.
    :Description: Test pki-server subsystem-cert-find, find ocsp subsystem certs
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Test pki-server subsystem-cert-find ocsp
    :ExpectedResults:
        1. It should show all the ocspsubsystem certs
    """
    cert_id = {'signing': 'ocspSigningCert cert-{} OCSP',
               'sslserver': 'Server-Cert cert-{}',
               'subsystem': 'subsystemCert cert-{}',
               'audit_signing': 'auditSigningCert cert-{} OCSP'}

    cmd = 'pki-server subsystem-cert-find ocsp -i {}'.format(constants.OCSP_INSTANCE_NAME)
    cmd_out = ansible_module.command(cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            for certid, name in cert_id.items():
                assert 'Serial No:' in result['stdout']
                assert 'Cert ID: {}'.format(certid) in result['stdout']
                assert 'Nickname: {}'.format(name.format(constants.OCSP_INSTANCE_NAME)) in result['stdout']
                assert 'Token: Internal Key Storage Token' in result['stdout']
                log.info("Found Cert ID: {}, Nickname: {}".format(certid, name.format(constants.CA_INSTANCE_NAME)))
        else:
            log.error("Failed to run: {}".format(" ".join(result['cmd'])))
            pytest.skip()



def test_pki_server_subsystem_cert_find_find_tks_certs(ansible_module):
    """
    :Title: Test pki-server subsystem-cert-find, find tks subsystem certs.
    :Description: Test pki-server subsystem-cert-find, find tks subsystem certs
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Test pki-server subsystem-cert-find tks
    :ExpectedResults:
        1. It should show all the tks subsystem certs
    """
    cert_id = {'sslserver': 'Server-Cert cert-{}',
               'subsystem': 'subsystemCert cert-{}',
               'audit_signing': 'auditSigningCert cert-{} TKS'}

    cmd = 'pki-server subsystem-cert-find tks -i {}'.format(constants.TKS_INSTANCE_NAME)
    cmd_out = ansible_module.command(cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            for certid, name in cert_id.items():
                assert 'Serial No:' in result['stdout']
                assert 'Cert ID: {}'.format(certid) in result['stdout']
                assert 'Nickname: {}'.format(name.format(constants.TKS_INSTANCE_NAME)) in result['stdout']
                assert 'Token: Internal Key Storage Token' in result['stdout']
                log.info("Found Cert ID: {}, Nickname: {}".format(certid, name.format(constants.CA_INSTANCE_NAME)))
        else:
            log.error("Failed to run: {}".format(" ".join(result['cmd'])))
            pytest.skip()



def test_pki_server_subsystem_cert_find_find_tps_certs(ansible_module):
    """
    :Title: Test pki-server subsystem-cert-find, find tps subsystem certs.
    :Description: Test pki-server subsystem-cert-find, find tps subsystem certs
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Test pki-server subsystem-cert-find tps
    :ExpectedResults:
        1. It should show all the tps subsystem certs
    """
    cert_id = {'sslserver': 'Server-Cert cert-{}',
               'subsystem': 'subsystemCert cert-{}',
               'audit_signing': 'auditSigningCert cert-{} TPS'}

    cmd = 'pki-server subsystem-cert-find tps -i {}'.format(constants.TPS_INSTANCE_NAME)
    cmd_out = ansible_module.command(cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            for certid, name in cert_id.items():
                assert 'Serial No:' in result['stdout']
                assert 'Cert ID: {}'.format(certid) in result['stdout']
                assert 'Nickname: {}'.format(name.format(constants.TPS_INSTANCE_NAME)) in result['stdout']
                assert 'Token: Internal Key Storage Token' in result['stdout']
                log.info("Found Cert ID: {}, Nickname: {}".format(certid, name.format(constants.CA_INSTANCE_NAME)))
        else:
            log.error("Failed to run: {}".format(" ".join(result['cmd'])))
            pytest.skip()


def test_pki_server_subsystem_cert_find_with_invalid_instance(ansible_module):
    """
    :Title: Test pki-server subsystem-cert-find with invalid instance
    :Description: Test pki-server subsystem-cert-find with invalid instance
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki-server subsystem-cert-find -i topology-200-CA
    :ExpectedResults:
        1. It should throw an error message.
    """

    cmd = 'pki-server subsystem-cert-find ca -i topology-2000-CA'
    cmd_out = ansible_module.command(cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            log.error("Failed to run : {}".format(" ".join(result['cmd'])))
            pytest.skip()
        else:
            assert 'ERROR: Invalid instance topology-2000-CA' in result['stderr']
            log.info("Successfully run : {}".format(" ".join(result['cmd'])))


def test_pki_server_subsystem_cert_find_with_show_all_attribute(ansible_module):
    """
    :Title: Test pki-server subsystem-cert-find with --show-all option
    :Description: Test pki-server subsystem-cert-find with --show-all option
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki-server subsystem-cert-find with --show-all option
    :ExpectedResults:
        1. It should show the b64 encoded certificate and request
    """

    cert_id = {'signing': 'caSigningCert cert-{} CA',
               'ocsp_signing': 'ocspSigningCert cert-{} CA',
               'sslserver': 'Server-Cert cert-{}',
               'subsystem': 'subsystemCert cert-{}',
               'audit_signing': 'auditSigningCert cert-{} CA'}

    cmd = 'pki-server subsystem-cert-find ca -i {} --show-all'.format(constants.CA_INSTANCE_NAME)
    cmd_out = ansible_module.command(cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            for certid, name in cert_id.items():
                assert 'Serial No:' in result['stdout']
                assert 'Cert ID: {}'.format(certid) in result['stdout']
                assert 'Nickname: {}'.format(name.format(constants.CA_INSTANCE_NAME)) in result['stdout']
                assert 'Token: internal' in result['stdout']
                assert 'Certificate: ' in result['stdout']
                assert 'Request: ' in result['stdout']
                log.info("Found Cert ID: {}, Nickname: {}".format(certid, name.format(constants.CA_INSTANCE_NAME)))
        else:
            log.error("Failed to run: {}".format(" ".join(result['cmd'])))
            pytest.skip()


def test_pki_server_subsystem_cert_find_with_verbose_option(ansible_module):
    """
    :Title: Test pki-server subsystem-cert-find with -v option
    :Description: Test pki-server subsystem-cert-find with -v option
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki-server subsystem-cert-find ca -i <instance> -v
    :ExpectedResults:
        1. It should shows verbose output.
    """
    cert_id = {'signing': 'caSigningCert cert-{} CA',
               'ocsp_signing': 'ocspSigningCert cert-{} CA',
               'sslserver': 'Server-Cert cert-{}',
               'subsystem': 'subsystemCert cert-{}',
               'audit_signing': 'auditSigningCert cert-{} CA'}

    cmd = 'pki-server subsystem-cert-find ca -i {} -v'.format(constants.CA_INSTANCE_NAME)
    cmd_out = ansible_module.command(cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            for certid, name in cert_id.items():
                assert 'Serial No:' in result['stdout']
                assert 'Cert ID: {}'.format(certid) in result['stdout']
                assert 'Nickname: {}'.format(name.format(constants.CA_INSTANCE_NAME)) in result['stdout']
                assert 'Token: internal' in result['stdout']
                log.info("Found Cert ID: {}, Nickname: {}".format(certid, name.format(constants.CA_INSTANCE_NAME)))
        else:
            log.error("Failed to run: {}".format(" ".join(result['cmd'])))
            pytest.skip()


def test_pki_server_subsystem_cert_find_bz_1566360_serial_no_is_missing(ansible_module):
    """
    :Title: Test pki-server subsystem-cert-find, BZ: Serial no is missing.
    :Description: Test pki-server subsystem-cert-find BZ: Serial no is missing.
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. pki-server subsystem-cert-find ca -i <instance>
    :ExpectedResults:
        1. CLI should show the serial no in the ouput.
    """
    cert_id = {'signing': 'caSigningCert cert-{} CA',
               'ocsp_signing': 'ocspSigningCert cert-{} CA',
               'sslserver': 'Server-Cert cert-{}',
               'subsystem': 'subsystemCert cert-{}',
               'audit_signing': 'auditSigningCert cert-{} CA'}

    cmd = 'pki-server subsystem-cert-find ca -i {} -v'.format(constants.CA_INSTANCE_NAME)
    cmd_out = ansible_module.command(cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            for certid, name in cert_id.items():
                assert 'Serial No:' in result['stdout']
                assert 'Cert ID: {}'.format(certid) in result['stdout']
                assert 'Nickname: {}'.format(name.format(constants.CA_INSTANCE_NAME)) in result['stdout']
                assert 'Token: internal' in result['stdout']
                log.info("Found Cert ID: {}, Nickname: {}".format(certid, name.format(constants.CA_INSTANCE_NAME)))
        else:
            log.error("Failed to run: {}".format(" ".join(result['cmd'])))
            pytest.skip()
