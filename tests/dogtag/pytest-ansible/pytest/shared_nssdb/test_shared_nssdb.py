#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Bug 1596889 Move PKI to shared NSS DB model
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

import pytest
import os
if os.path.isfile('/tmp/test_dir/constants.py'):
    import sys
    sys.path.append('/tmp/test_dir')
    import constants


def test_shared_nssdb(ansible_module):
    """
    :id: 72edf507-75e5-4839-81e3-7fed4517225b

    :Title: Dogtag PKI should use the shared NSS DB model

    :Description: Bug 1596889 - Dogtag PKI should use the shared NSS DB model

    :Requirement: NSS SQL Database Support

    :Setup:
        1. Setup Dogtag PKI using ansible playbooks

    :Steps:
        1. Setup CA/KRA

    :Expectedresults:
        1. CA, KRA setup should succeed and the nss database should be in the new format as follows
           [root@rhel8-pki-permanent ~]# ls nssdb/
           cert9.db  key4.db  pkcs11.txt

    :Automated: Yes
    """
    create_nssdb = ansible_module.command("pki -d {} -c {} client-init".format(constants.NSSDB,
                                                                               constants.CLIENT_DIR_PASSWORD))

    for result in create_nssdb.values():
        assert result['rc'] == 0

    list_nssdb = ansible_module.command("ls {}".format(constants.NSSDB))
    for result in list_nssdb.values():
        assert "key4.db" in result['stdout']
        assert "cert9.db" in result['stdout']
        assert "pkcs11.txt" in result['stdout']

    ansible_module.command("rm -rf {}".format(constants.NSSDB))

def test_shared_client_nssdb(ansible_module):
    """
    :id: e09ca14c-269c-4b03-8bd3-00573c4004f0

    :Title: Dogtag PKI client NSS DB should use the shared NSS DB model

    :Description: Bug 1596889 -Dogtag PKI client NSS DB should use the shared NSS DB model

    :Requirement: NSS SQL Database Support

    :Setup:
        1. Setup Dogtag PKI using ansible playbooks

    :Steps:
        1. Setup CA/KRA
        2. Create NSSDB using an older version of dogtag pki which did not use the shared NSS DB model
        3. Run the following command which migrates the older DBM format to the newer shared NSS DB
           certutil -d sql:/path/to/database -N -f
           /path/to/database/password/file -@ /path/to/database/password/file

    :Expectedresults:
        1. CA/KRA should be setup successfully
        2. NSSDB should be created with an older dogtag pki build (pre shared NSS DB format). Client
           database should be created
        3. certutil command should ensure the client NSS database is migrated to the structure below
           [root@rhel8-pki-permanent ~]# ls nssdb/
           cert9.db  key4.db  pkcs11.txt

    :Automated: No
    """