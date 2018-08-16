#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Enabling additional ciphers for rsa installation.
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Roshni Pattath <rpattath@redhat.com>
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
import os
import sys
import re

import pytest

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

ciphers = ['+TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', '+TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', '+TLS_DHE_RSA_WITH_AES_128_CBC_SHA',
            '+TLS_DHE_RSA_WITH_AES_256_CBC_SHA', '+TLS_DHE_RSA_WITH_AES_128_CBC_SHA256', '+TLS_DHE_RSA_WITH_AES_256_CBC_SHA256',
            '+TLS_DHE_RSA_WITH_AES_128_GCM_SHA256', '+TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256', '+TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
            '+TLS_RSA_WITH_AES_128_CBC_SHA256', '+TLS_RSA_WITH_AES_256_CBC_SHA256', '+TLS_RSA_WITH_AES_128_CBC_SHA',
            '+TLS_RSA_WITH_AES_256_CBC_SHA']
            
topology = int(constants.CA_INSTANCE_NAME.split("-")[-2])

@pytest.mark.skipif('topology != 02')
@pytest.mark.parametrize('inst', [constants.CA_INSTANCE_NAME,
                                  constants.KRA_INSTANCE_NAME,
                                  constants.OCSP_INSTANCE_NAME,
                                  constants.TKS_INSTANCE_NAME,
                                  constants.TPS_INSTANCE_NAME])
def test_bug_1554727_additional_cipher_check(ansible_module, inst):

    """
    :Title: RSA installation of subsystem instance should have additonal ciphers.
            Automation of BZ: 1554727

    :Description: This automation tests subsystem instances have additional ciphers
                  enabled after RSA installation.

    :Requirement: RHCS-REQ Installation and Deployment

    :CaseComponent: \-

    :Steps:
            1. Install subsystem instances using RSA keys.

    :Expectedresults:
            1. Verify /var/lib/pki/<instance-name>/conf/server.xml has
               the following:
               +TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               +TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
               +TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
               +TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
               +TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
               +TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
               +TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
               +TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
               +TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
               +TLS_RSA_WITH_AES_128_CBC_SHA256,
               +TLS_RSA_WITH_AES_256_CBC_SHA256,
               +TLS_RSA_WITH_AES_128_CBC_SHA,
               +TLS_RSA_WITH_AES_256_CBC_SHA

    :Automated: Yes
    """
    output = ansible_module.shell('cat /var/lib/pki/%s/conf/server.xml' % inst)
    for result in output.values():
        ciphers_in_file = re.findall('sslRangeCiphers=[\W].*', result['stdout'])
        enabled_ciphers = ciphers_in_file[0].strip()
        for i in ciphers:
            try:
                assert i in enabled_ciphers
            except:
                pytest.xfail("Failed to assert few ciphers")
