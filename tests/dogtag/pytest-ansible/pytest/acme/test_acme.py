"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: acme test cases automation
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Deepak Punia
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
import logging
import requests, urllib3
from pki.testlib.common.certlib import os, sys, pytest
import re
import random
import time

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
challenge = ["http"]
acme_url = "http://{}:{}/acme/directory".format(constants.MASTER_HOSTNAME, constants.CA_HTTP_PORT)


def test_acme_url_status():
    """
    :Title: Test acme url status.
    :id: b1867539-c636-4550-8d3e-3f33277389d0
    :Description: test acme running status
    :Requirement: ACME Certificate Provisioning
    :Setup: Use the acme setup in ansible to setup the environment
    :Steps:
        1. Use the request module to check the acme url running status.
            https://$HOSTNAME:8443/acme/directory
    :Expected results:
        1. acme should be in running status and url should be accessible
    """
    time.sleep(20)
    response = requests.get('https://{}:{}/acme/directory'.format(constants.MASTER_HOSTNAME, constants.CA_HTTPS_PORT),
                            verify=False)
    if response.status_code == 200:
        assert "https://{}:{}/acme/new-nonce".format(constants.MASTER_HOSTNAME,
                                                     constants.CA_HTTPS_PORT) in response.text
        log.info("Successfully run : {}".format(response.status_code))
    else:
        log.error("Failed to run : {}".format(response.status_code))
        pytest.fail()


def test_acme_domain_certificate_enrollment_with_automatic_http_validation(ansible_module):
    """
    :Title: Certificate Enrollment with domain certificate enrollment with automatic http-01 validation
    :id: eec13632-f82a-448f-b5e2-28204c166087
    :Description: Certificate Enrollment with domain certificate enrollment with automatic http-01 validation
    :Requirement: ACME Certificate Provisioning
    :Setup: Use the acme setup in ansible to setup the environment
    :Steps:
        1. Use the client certbot to send the domain certificate enrollment with automatic http-01 validation
            #certbot certonly --standalone --server http://$HOSTNAME:8080/acme/directory -d pki1.example.com
                    --preferred-challenges http --register-unsafely-without-email
    :Expected results:
        1. acme domain enrollment should be successful without any issue.
    """
    cmd = "certbot certonly --standalone --server {} -d {} --preferred-challenges " \
          "{} --register-unsafely-without-email --agree-tos"
    time.sleep(10)
    cmd_out = ansible_module.command(cmd.format(acme_url, constants.MASTER_HOSTNAME, challenge[0]))

    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Your certificate and chain have been saved" in result['stdout']

            for f in re.findall(".+live.+pem", result['stdout']):
                f_loc = f.strip("   ")
                file_stat = ansible_module.stat(path=f_loc)
                for results in file_stat.values():
                    if results['stat']['exists'] == True:
                        log.info("Successfully find cert file : '{}'".format(results['stat']))
                    else:
                        log.info("Failed to find cert file: '{}'".format(result['stat']))
                        pytest.fail()
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.fail()


def test_acme_domain_certificate_renew_with_automatic_http_validation(ansible_module):
    """
    :Title: Certificate renew with domain certificate
    :id: 0385ce80-bb3d-41a5-877d-482f0f83fbbb
    :Description: Certificate renew with domain certificate enrollment with automatic http-01 validation
    :Requirement: ACME Certificate Provisioning
    :Setup: Use the acme setup in ansible to setup the environment
    :Steps:
        1. Use the client certbot to send the domain certificate renew with automatic http-01 validation.
            #certbot certonly --standalone --server http://$HOSTNAME:8080/acme/directory -d pki1.example.com
                    --preferred-challenges http --register-unsafely-without-email
            Note: Certificate renew will use same command like it enroll the certificate.
    :Expected results:
        1. acme domain enrollment should be successful without any issue.
    """
    cmd = "certbot certonly --standalone --server {} -d {} --preferred-challenges " \
          "{} --register-unsafely-without-email"

    cmd_out = ansible_module.expect(command=cmd.format(acme_url, constants.MASTER_HOSTNAME, challenge[0]),
                                    responses={"\(press \'c\' to cancel\)": 2})

    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Renewing an existing certificate" in result['stdout']
            #assertion message MaxRetryError to verify the bugzilla 1868233
            assert "ConnectionError: HTTPConnectionPool(host='ocsp.example.com', port=80)" not in result['stdout']
            for f in re.findall(".+live.+pem", result['stdout']):
                f_loc = f.strip("   ")
                file_stat = ansible_module.stat(path=f_loc)
                for results in file_stat.values():
                    if results['stat']['exists'] == True:
                        log.info("Successfully find cert file : '{}'".format(results['stat']))
                    else:
                        log.info("Failed to find cert file: '{}'".format(result['stat']))
                        pytest.fail()
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.fail()


def test_acme_deactivate_account(ansible_module):
    """
    :Title: Deactivate acme Account
    :id: 7b4bece3-d9a6-4815-b03c-6d5c9345c535
    :Description: Deactivate the ACME Account by using acme client
    :Requirement: ACME Certificate Provisioning
    :Setup: Use the acme setup in ansible to setup the environment
    :Steps:
        1. Create the account first but here account is already created while enrollment in above test case.
        2. Use the client certbot to send the deactivation required.
             #certbot unregister --server http://$HOSTNAME:8080/acme/directory

    :Expected results:
        1. Account should be Deactivated
    """
    cmd = "certbot unregister --server {}"
    cmd_out = ansible_module.expect(command=cmd.format(acme_url), responses={"\(D\)eactivate\/\(A\)bort": 'D'})
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Account deactivated" in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.fail()


def test_acme_create_account(ansible_module):
    """
    :Title: Create/register acme Account
    :id: 8495948f-4e2c-4a46-995e-8cace4b1692c
    :Description: Create the ACME Account by using acme client
    :Requirement:
    :Setup: Use the acme setup in ansible to setup the environment
    :Steps:
        1. Use the client certbot to send the deactivation required.
             #certbot register --server http://$HOSTNAME:8080/acme/directory -m user@example.com --agree-tos

    :Expected results:
        1. Account should be Deactivated
    """
    cmd = "certbot register --server {} -m user@example.com --agree-tos"
    cmd_out = ansible_module.expect(command=cmd.format(acme_url), responses={"\(Y\)es\/\(N\)o": 'Y'})
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Account registered" in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.fail()


def test_acme_update_account(ansible_module):
    """
    :Title: Update acme Account
    :id: 84477d7d-b649-41dc-9f98-b84b8c733147
    :Description: Update the ACME Account by using acme client
    :Requirement: ACME Certificate Provisioning
    :Setup: Use the acme setup in ansible to setup the environment
    :Steps:
        1. Use the client certbot to send the update account.
             #certbot update_account --server http://$HOSTNAME:8080/acme/directory -n -m root@example.com

    :Expected results:
        1. Account should be mail should be updated.
    """
    acme_user = 'acme{}'.format(random.randint(1111, 99999999))
    cmd = "certbot update_account --server {} -n -m {}@example.com"
    cmd_out = ansible_module.command(cmd.format(acme_url, acme_user))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Your e-mail address was updated to {}@example.com".format(acme_user) in result['stdout']
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            assert result['rc'] >= 1
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.fail()

    for dt in ['/etc/letsencrypt/accounts/', '/etc/letsencrypt/live/']:
        ansible_module.shell('rm -rf {}'.format(dt))
        log.info('Successfully removed files')


