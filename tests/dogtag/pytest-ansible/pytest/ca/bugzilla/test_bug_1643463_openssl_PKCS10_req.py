#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: 1643463 - Extra line in PKCS10Client request, not able to recognized by openssl
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Shalini Khandelwal <skhandel@redhat.com>
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
import os
import random
import sys
import pytest


try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)


def test_bz_1643463_openssl_PKCS10_req(ansible_module):
    """
    :id: be68612f-b3f1-4ee6-80c3-7df8b6b90907
    :Title: Bug 1643463 - Extra line in PKCS10Client request, not able to recognized by openssl
    :Description: Bug 1643463 - Extra line in PKCS10Client request, not able to recognized by openssl
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :Setup:
        1. PKI Packages installed
    :Steps:
        1. Generate a PKCS10 request using following command :
        PKCS10Client -d <nssdb> -p <password> -a rsa -l 2048 -o <outputfile> -n <certificate subject>'
        2. Run openssl command to read generated request file.
        eg: openssl req -in /tmp/testuser1_nistp384.req -noout -text
    :Expectedresults:
        1. PKCS10 request file generated successfully.
        2. openssl command should be able to read the generated request file without any error.
    :Automated: Yes
    :CaseComponent: \-
    """

    nssdb = '/tmp/nssdb'
    userid = 'testuser{}'.format(random.randint(111, 999))
    subject = 'UID={},CN={}'.format(userid, userid)
    request_file = '/tmp/{}.pem'.format(userid)

    client_init_cmd = 'pki -d {} -c {} client-init --force'.format(nssdb, constants.CLIENT_DATABASE_PASSWORD)
    create_nssdb_out = ansible_module.command(client_init_cmd)
    result = create_nssdb_out.values()[0]

    if result['rc'] != 0:
        log.error('Failed to generate temporary nssdb')
        log.error("Failed to ran : '{}'".format(result['cmd']))
        log.error(result['stderr'])
        pytest.fail()

    pkcs10cmd = 'PKCS10Client -d {} -p {} -a rsa -l 2048 -o {} -n {}'.format(
        nssdb, constants.CA_PASSWORD, request_file, subject)
    pkcs10_out = ansible_module.command(pkcs10cmd)
    result = pkcs10_out.values()[0]

    if result['rc'] != 0:
        log.error('Failed to generate PKCS req file')
        log.error("Failed to ran : '{}'".format(result['cmd']))
        log.error(result['stderr'])
        log.error(result['stdout'])
        pytest.fail()

    openssl_cmd = 'openssl req -in {} -noout -text'
    openssl_out = ansible_module.command(openssl_cmd.format(request_file))
    result = openssl_out.values()[0]

    if result['rc'] == 0:
        assert 'Certificate Request' in result['stdout']
        assert userid in result['stdout']
    else:
        log.error("Failed to ran : '{}'".format(result['cmd']))
        log.error(result['stderr'])
        pytest.fail()

    ansible_module.command('rm -rf {} {}'.format(nssdb, request_file))
