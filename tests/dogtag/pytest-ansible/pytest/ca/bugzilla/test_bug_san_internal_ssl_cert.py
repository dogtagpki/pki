#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Bug 1562423 - SAN in internal SSL server certificate
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Sumedh Sidhaye <ssidhaye@redhat.com>
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
import re
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
TOPOLOGY = int(constants.CA_INSTANCE_NAME.split("-")[-2])


@pytest.mark.skipif("TOPOLOGY != 2")
def test_bug_1562423_san_internal_ssl_cert(ansible_module):
    """
    :Title: Bug 1562423 - SAN in internal SSL server certificate

    :Description: Bug 1562423 - SAN in internal SSL server certificate
    :Setup:
        1. Setup DS
        2. Setup CA
        3. Setup KRA
        4. Setup Sub CA
    :Steps:
        1. Install CA (single step) and check that its SSL server cert
           bears the Subject Alternative Name (SAN) extension that matches the CN of the cert
        2. Install KRA (single step on a separate tomcat instance) and check that its SSL SSL server cert
           bears the Subject Alternative Name (SAN) extension that matches the CN of the cert
        3. Install Sub CA and check that its SSL SSL server cert
           bears the Subject Alternative Name (SAN) extension that matches the CN of the cert
        4. Create a CMC request and submit per CMC enrollment procedure and check that
           its SSL SSL server cert bears the Subject Alternative Name (SAN)
           extension that matches the CN of the cert
    :Expectedresults:
        1. CA installation should succeed and SSL server cert bears the Subject Alternative Name (SAN)
           extension that matches the CN of the cert
        2. KRA installation should succeed and SSL server cert bears the Subject Alternative Name (SAN)
           extension that matches the CN of the cert
        3. Sub CA installation should succeed and SSL server cert bears the Subject Alternative Name (SAN)
           extension that matches the CN of the cert
        4. CMC Enrollment should succeed. Use the config files attached for reference.
    :Automated: No
    :CaseComponent: \-
    """
    instance_path = '/var/lib/pki/{}/'.format(constants.CA_INSTANCE_NAME)
    alias_db = os.path.join(instance_path, 'alias')
    cs_cfg_path = os.path.join(instance_path, 'ca/conf/CS.cfg')
    sslserver_nick = ''

    get_nickname = ansible_module.command('grep -ir "ca.cert.sslserver.nickname=" {}'.format(cs_cfg_path))
    for result in get_nickname.values():
        if result['rc'] == 0:
            sslserver_nick = result['stdout'].split("=")[1].strip()
        else:
            pytest.fail("Failed to get SSL server nickname.")
    list_cert = ansible_module.command('certutil -L -d {} -n "{}"'.format(alias_db, sslserver_nick))
    for result in list_cert.values():
        if result['rc'] == 0:
            get_cn = re.findall('Subject:.*', result['stdout'])
            cn = get_cn[0].split(":")[1].split(",")[0].split("=")[1].strip()

            get_san = re.findall("DNS name.*", result['stdout'])
            san = get_san[0].split(":")[1].strip()

            assert cn in san
        else:
            log.error("")
            pytest.fail()
