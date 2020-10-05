"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Pki Server CA-CERT-REQUEST CLI TESTS
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki-server cli commands needs to be tested:
#   pki-server ca-cert-request
#   pki-server ca-cert-request-find
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

import random
import sys

import os
import pytest
import logging

from pki.testlib.common import utils

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

userop = utils.UserOperations(nssdb=constants.NSSDB)
BASE_DB_DIR = '/var/lib/pki/{}/alias'

TOPOLOGY = constants.CA_INSTANCE_NAME.split("-")[-2]

if TOPOLOGY == '01':
    ca_instance_name = 'pki-tomcat'
    topology_name = 'topology-01-CA'
else:
    ca_instance_name = constants.CA_INSTANCE_NAME
    topology_name = constants.CA_INSTANCE_NAME


def create_cert(ansible_module):
    """
    Return a base 64 encoded certificate.
    """
    no = random.randint(11, 999989)
    user = 'testuser{}'.format(no)
    subject = 'UID={},CN={}'.format(user, user)

    cert_id = userop.process_certificate_request(ansible_module, subject=subject)
    if cert_id:
        cert_file = "/tmp/{}.pem".format(user)
        ansible_module.shell('pki -d {} -c {} -p {} client-cert-import "{}" '
                               '--serial {}'.format(constants.NSSDB, constants.CLIENT_DIR_PASSWORD,
                                                    constants.CA_HTTP_PORT, user, cert_id))
        ansible_module.shell('pki -d {} -c {} client-cert-show "{}" '
                               '--cert /tmp/{}.pem '.format(constants.NSSDB,
                                                            constants.CLIENT_DIR_PASSWORD,
                                                            user, user))
        ansible_module.shell('pki -d {} -c {} client-cert-del '
                               '"{}"'.format(constants.NSSDB, constants.CLIENT_DIR_PASSWORD,
                                             user))
        return [cert_id, cert_file]


def test_pki_server_ca_cert_request(ansible_module):
    """
    :id: 5ac753d1-b815-4086-af23-6aca3cd7a864
    :Title: Test pki-server ca-cert-request command
    :Description: test pki-server ca-cert-request command
    :Requirement: Pki Server CA
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :CaseComponent: \-
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server ca-cert-request command shows ca-cert-request-find,
           ca-cert-request-find commands.
    """
    ca_cert_out = ansible_module.shell('pki-server ca-cert-request')
    for result in ca_cert_out.values():
        if result['rc'] == 0:
            assert "ca-cert-request-find          Find CA certificate requests" in result['stdout']
            assert "ca-cert-request-show          Show CA certificate request" in result['stdout']
        else:
            pytest.fail("Failed to run pki-server ca-cert-request-find command.")


def test_pki_server_ca_cert_request_find(ansible_module):
    """
    :id: 1d2a3723-3fb4-4f22-af11-e9519cfa8a66
    :Title: Bug - 1289605 : Test pki-server ca-cert-request-find command should find
            the certificate request with the default pki-tomcat instance.
    :Description: Bug-1289605, Test pki-server ca-cert-request-find command should find
        the certificate request with the default pki-tomcat instance.
    :Requirement: Pki Server CA
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :CaseComponent: \-
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server ca-cert-request-find command shows the cert
           request with default pki-tomcat instance.
    """
    cmd = 'pki-server ca-cert-request-find -i {}'.format(ca_instance_name)
    request_out = ansible_module.shell(cmd)
    for result in request_out.values():
        if result['rc'] >= 1:
            assert "ERROR: 'extdata-cert--005frequest'" in result['stderr']
        else:
            assert "entries matched" in result['stdout']
            assert "Request ID:" in result['stdout']
            assert "Type: enrollment" in result['stdout']
            assert "Status: " in result['stdout']


@pytest.mark.parametrize("instance_name", [ca_instance_name, "invalid_instance"])
def test_pki_server_ca_cert_request_find_with_instance_name(ansible_module, instance_name):
    """
    :id: 30b662b4-4371-4829-86c9-4d84dc8f4b09
    :Title: Test pki-server ca-cert-request-find -i <instance_name> command
    :Description: Test pki-server ca-cert-request-find -i <instance_name> command
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :CaseComponent: \-
    :Requirement: Pki Server CA
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server ca-cert-request-find -i <instance_name> command
           shows the cert request.
    """
    cmd = 'pki-server ca-cert-request-find -i {}'.format(instance_name)

    request_out = ansible_module.shell(cmd)
    for result in request_out.values():
        if result['rc'] >= 1:
            if 'Invalid' in result['stderr']:
                assert "ERROR: Invalid instance: %s" % instance_name in result['stderr']
            else:
                assert "ERROR: 'extdata-cert--005frequest'" in result['stderr']
        else:
            assert "entries matched" in result['stdout']
            assert "Request ID:" in result['stdout']
            assert "Type: enrollment" in result['stdout']
            assert "Status: " in result['stdout']


@pytest.mark.skip(reason="Not implemented correctly")
def test_pki_server_ca_cert_request_find_with_cert_option(ansible_module):
    """
    :id: 08997b38-1f9c-4b18-8863-10efd400302a
    :Title: Test pki-server ca-cert-request-find with --cert option.
    :Description: Test pki-server ca-cert-request-find with --cert option.
    :Requirement: Pki Server CA
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :Expectedresults:
                1. Command should show the certificate request after passing the certificate.
    """
    cert_id, cert_file = create_cert(ansible_module)

    cert_out = ansible_module.shell('pki-server ca-cert-request-find '
                                      '-i {} --cert {}'.format(ca_instance_name, cert_id))

    for result in cert_out.values():
        if result['rc'] == 0:
            if '0 entries matched' in result['stdout']:
                pytest.fail("Failed to run pki-server ca-cert-request-find.")
            elif '0 entries matched' not in result['stdout']:
                assert 'Request ID: ' in result['stdout']
                assert 'Type:' in result['stdout']
                assert 'Status:' in result['stdout']
            else:
                pytest.fail("Failed to run pki-server ca-cert-request-find.")


@pytest.mark.skip(reason="Not implemented correctly")
def test_pki_server_ca_cert_request_find_with_cert_file_option(ansible_module):
    """
    :id: 3237f537-b262-4698-b10f-4b907fa4a961
    :Title: Test pki-server ca-cert-request-find with cert-file option
    :Description: Test pki-server ca-cert-request-find with cert-file option.
    :Requirement: Pki Server CA
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :Expectedresults:
        1. It should show the certificate request when certificate file is passed.
    """
    cert_id, cert_file = create_cert(ansible_module)

    cert_out = ansible_module.shell('pki-server ca-cert-request-find '
                                      '-i {} --cert-file {}'.format(ca_instance_name, cert_file))

    for result in cert_out.values():
        if result['rc'] == 0:
            if '0 entries matched' in result['stdout']:
                pytest.fail("Failed to run pki-server ca-cert-request-find.")
            elif '0 entries matched' not in result['stdout']:
                assert 'Request ID: ' in result['stdout']
                assert 'Type:' in result['stdout']
                assert 'Status:' in result['stdout']
            else:
                pytest.fail("Failed to run pki-server ca-cert-request-find.")
