#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: HAProxy rejects OCSP responses due to missing
#   nextupdate field automation
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
import os
import sys
import re
import tempfile
import time
try:
    from pki.testlib.common import constants
except Exception:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants


def test_bug_1523443_HAProxy_rejection(ansible_module):
    """
    :id: e7472e90-aba5-40af-8c7c-d29507397a59

    :Title: Bug 1523443 - HAProxy rejects OCSP responses due to missing nextupdate field

    :Description: The automation will verify that after adding ca.ocspUseCache=true in CS.cfg
    OCSP response contains 'nextUpdate' field

    :Requirement: Certificate Authority OSCP

    :Setup:
        Dogtagpki is setup via ansible playbooks

    :Steps:
        1. install dogtag
        2. set ca.ocspUseCache=true in CS.cfg and restart instance
        3. perform a OCSP request and verify that the OCSP response contains the nextUpdate \
        field using the following command:
        openssl ocsp -CAfile ca.crt -issuer ca.crt -url http://<hostname>:<port>/ca/ocsp \
        -serial <serial no> -no_nonce

    :Expectedresults:
        1. Dogtag should be setup successfully
        2. ca.ocspUseCache=true should be set in CS.cfg and the instance should be successfully restarted
        3. Step 3 should result in the a similar output as below:
        Response verify OK
        <serial_number>: good
        This Update: Jan 31 05:52:39 2018 GMT
        Next Update: Jan 31 06:00:00 2018 GMT

    :Automated: Yes

    :CaseComponent: \-
    """
    temp_dir = tempfile.mkdtemp(suffix="_test", prefix='profile_', dir="/tmp/")
    ca_cs_cfg = os.path.join(temp_dir, '/CS.cfg')
    ansible_module.shell('systemctl stop pki-tomcatd@%s.service' % constants.CA_INSTANCE_NAME)
    ansible_module.fetch(src='/var/lib/pki/%s/ca/conf/CS.cfg' % constants.CA_INSTANCE_NAME,
                         dest=ca_cs_cfg, flat=True)
    if os.path.isfile(ca_cs_cfg):
        with open(ca_cs_cfg, 'r') as input_file, open('/tmp/CS.cfg', 'w') as output_file:
            for line in input_file:
                if line.strip() == 'ca.ocspUseCache=false':
                    output_file.write('ca.ocspUseCache=true\n')
                else:
                    output_file.write(line)

    ansible_module.copy(src='/tmp/CS.cfg',
                        dest="/var/lib/pki/%s/ca/conf/CS.cfg" % constants.CA_INSTANCE_NAME)
    ansible_module.shell('systemctl start pki-tomcatd@%s.service' % constants.CA_INSTANCE_NAME)
    time.sleep(10)
    cert_find_output = ansible_module.shell("pki -d %s -c %s -p %s ca-cert-find --name 'CA Signing'" %
                                              (constants.NSSDB, constants.CLIENT_DATABASE_PASSWORD,
                                               constants.CA_HTTPS_PORT))
    cert_serial = None
    cert_serial = re.findall("Serial Number\: [0-9a-zA-Z]+", cert_find_output.values()[0]['stdout'])
    cert_serial = cert_serial[0].split(':')[1].strip()
    cert_show_output = ansible_module.shell('pki -d %s -p %s cert-show %s --output /tmp/ca.crt' %
                                              (constants.NSSDB, constants.CA_HTTPS_PORT, cert_serial))
    for result in cert_show_output.values():
        assert "Serial Number: %s" % cert_serial in result['stdout']
        assert "Status: VALID" in result['stdout']
    openssl_output = ansible_module.shell('openssl ocsp -CAfile /tmp/ca.crt -issuer /tmp/ca.crt \
                                            -url http://pki1.example.com:%s/ca/ocsp -serial %s \
                                            -no_nonce' % (constants.CA_HTTP_PORT, cert_serial))

    for result in openssl_output.values():
        assert "Response verify OK" in result['stderr_lines']
        assert "1: good" in result['stdout']
        assert "This Update:" in result['stdout']