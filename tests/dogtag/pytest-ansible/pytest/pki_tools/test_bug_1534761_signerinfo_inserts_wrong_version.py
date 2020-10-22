#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Bug 1534761 - SignerInfo class inserts wrong version # into the resulting structure
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
import os
import sys
import tempfile

import pytest

try:
    from pki.testlib.common import constants
except Exception:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

def test_bug_1534761_SignerInfo_inserts_wrong_version(ansible_module):
    """
    :id: 0651ca4b-7465-4e58-a0d2-f68fce00e2bf

    :Title: Bug 1534761 - SignerInfo class inserts wrong version # into the resulting structure

    :Description: ug 1534761 - SignerInfo class inserts wrong version # into the resulting structure

    :Requirement: RHCS-REQ: Tools

    :Setup: Use RHCS setup via ansible playbooks

    :Steps:
        1. yum install java-1.8.0-openjdk-devel
        2. download test program test.java
        3. mkdir nssdb && certutil -d nssdb -N
        4. compile test program: javac -classpath /usr/lib/java/jss4.jar test.java
        5. Run test program: java -classpath /usr/lib/java/jss4.jar:. Main nssdb
           Provide password from step 2.

    :Expectedresults:
        1. java-1.8.0-openjdk-devel should be installed
        2. test.java program should be downloaded, to be later used in step 5.
        3. nssdb should be created and the password should be set
        4. test.java should compile successfully
        5. Output should match as given below:
            Enter password for NSS FIPS 140-2 User Private Key

            Version (should be 1) = 1
            Version (should be 3) = 3
            whereas the older version will have `3' on both lines:

                  Version (should be 1) = 3
                  Version (should be 3) = 3

    :Automated: Yes

    :CaseComponent: \-
    """
    temp_dir = tempfile.mkdtemp()

    client_init_output = ansible_module.command('pki -d %s -c %s client-init'
                                                % (temp_dir, constants.CLIENT_DIR_PASSWORD))
    for result in client_init_output.values():
        assert result['rc'] == 0

    try:
        ansible_module.command('javac -classpath /usr/lib/java/jss4.jar /tmp/test.java')
    except RuntimeError as runerr:
        print(runerr)
        pytest.fail("test.java compilation failed")

    expect_output = ansible_module.expect(chdir='/tmp', command='java -classpath /usr/lib/java/jss4.jar:/usr/share/java/slf4j/api.jar:. Main %s' % temp_dir,
                          responses={'Enter password for Internal Key Storage Token':constants.CLIENT_DIR_PASSWORD})

    for result in expect_output.values():
        assert "Version (should be 1) = 1" in result['stdout']
        assert "Version (should be 3) = 3" in result['stdout']




