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

from pki.testlib.common import utils

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

userop = utils.UserOperations(nssdb=constants.NSSDB)

BASE_DB_DIR = '/var/lib/pki/{}/alias'


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
        ansible_module.command('pki -d {} -c {} -p {} client-cert-import "{}" '
                               '--serial {}'.format(constants.NSSDB, constants.CLIENT_DIR_PASSWORD,
                                                    constants.CA_HTTP_PORT, user, cert_id))
        ansible_module.command('pki -d {} -c {} client-cert-show "{}" '
                               '--cert /tmp/{}.pem '.format(constants.NSSDB,
                                                            constants.CLIENT_DIR_PASSWORD,
                                                            user, user))
        ansible_module.command('pki -d {} -c {} client-cert-del '
                               '"{}"'.format(constants.NSSDB, constants.CLIENT_DIR_PASSWORD,
                                             user))
        return [cert_id, cert_file]


@pytest.mark.parametrize("instance_name", [constants.CA_INSTANCE_NAME, "invalid_instance"])
def test_pki_server_ca_cert_request_show(ansible_module, instance_name):
    """
    :id: 5b1aaaac-1cf3-4b5b-a6ba-f86db04a4042
    :Title: Test pki-server ca-cert-request-show command, BZ: 1289605
    :Description: Test pki-server ca-cert-request-show command. BZ: 1289605
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :CaseComponent: \-
    :Steps:
    :Requirement: Pki Server CA
    :ExpectedResults:
        1. Verify whether pki-server ca-cert-request-show command shows the
           specified request id.
    """
    cmd = 'pki-server ca-cert-request-show 1 -i {}'.format(instance_name)

    cmd_out = ansible_module.command(cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Request ID:" in result['stdout']
            assert "Type: enrollment" in result['stdout']
            assert "Status: complete" in result['stdout']
            assert "Request:" in result['stdout']
        else:
            assert "ERROR: Invalid instance %s" % instance_name in result['stdout']


@pytest.mark.parametrize("instance_name", [constants.CA_INSTANCE_NAME,
                                           "invalid_instance"])
def test_pki_server_ca_cert_request_show_with_instance_name(ansible_module, instance_name):
    """
    :id: 791544da-d5eb-42b5-8b4a-8728f10064bd
    :Title: Bug - 1289605 : Test pki-server ca-cert-request-show -i <instance_name>
            command, it should fail on invalid instance name.
    :Description: Test pki-server ca-cert-request-show -i <instance> command. Should failed with
            invalid instance name.
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :CaseComponent: \-
    :Requirement: Pki Server CA
    :Steps:
    :ExpectedResults:
        1. Verify whether pki-server ca-cert-request-show -i <instance_name> command shows
            the specified request id, and should fail on invalid instance name.
    """
    cmd = 'pki-server ca-cert-request-show 1 -i {}'.format(instance_name)

    cmd_out = ansible_module.command(cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Request ID: 1" in result['stdout']
            assert "Type: enrollment" in result['stdout']
            assert "Status: complete" in result['stdout']
            assert "Request:" in result['stdout']
        else:
            assert "ERROR: Invalid instance %s." % instance_name in result['stdout']


def test_pki_server_ca_cert_request_show_with_output_file(ansible_module):
    """
    :id: 72679079-f7ae-4452-9a54-df9bd1e0d862
    :Title: Test pki-server ca-cert-request-show with --output-file
    :Description: Test pki-server ca-cert-request-show with --output-file
    :Requirement: Pki Server CA
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
    :Expectedresults:
            1. Certificate request get stored in the output file.
    """

    cmd = 'pki-server ca-cert-request-show 1 -i {} ' \
          '--output-file /tmp/request1.req'.format(constants.CA_INSTANCE_NAME)

    req_out = ansible_module.command(cmd)
    for result in req_out.values():
        if result['rc'] == 0:
            is_file = ansible_module.stat(path='/tmp/request1.req')
            for res in is_file.values():
                assert res['stat']['exists']

            print_file = ansible_module.command('cat /tmp/request1.req')
            for res in print_file.values():
                if res['rc'] == 0:
                    assert '-----BEGIN CERTIFICATE REQUEST-----' in res['stdout']
                    assert '-----END CERTIFICATE REQUEST-----' in res['stdout']
        else:
            pytest.xfail("Failed to run pki-server ca-cert-request-show --output-file.")