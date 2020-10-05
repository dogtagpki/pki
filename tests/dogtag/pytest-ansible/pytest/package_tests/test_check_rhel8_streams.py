#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Renaming stream branches in PKI 10.6 modules
#                for RHEL 8.1
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Amol Kahat <akahat@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2019 Red Hat, Inc. All rights reserved.
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
import re
import sys
from distutils.version import LooseVersion, StrictVersion

import pytest

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)


def test_pki_bz_1715950_check_package_streams(ansible_module):
    """
    :Title: Test bug 1715950 check package streams
    :Description: Test bug 1715959 check package streams
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Check the package streams
    :ExpectedResults:
        1. It should be grater than or equal to 10.6
    """

    stream_out = ansible_module.command('dnf module info pki-core')
    for result in stream_out.values():
        if result['rc'] == 0:
            get_version = re.findall("Stream .*", result['stdout'])
            version = get_version[0].split(":")[1].strip()
            assert StrictVersion("10.6") >= LooseVersion(version)
            log.info("Correct packages are enabled.")
        else:
            log.error(result['stderr'])
            pytest.fail("Failed to verify the packages.")


def test_pki_bz_1719163_rebase_pki_core(ansible_module):
    """
    :Title: Test pki bz 1719163 rebase pki-core
    :Description: Test pki bz 1719163 rebase pki-core
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Check module version
    :ExpectedResults:
        1. It should be grater than or equal to 10.6
    """
    stream_out = ansible_module.command('dnf module info pki-core')
    for result in stream_out.values():
        if result['rc'] == 0:
            get_version = re.findall("Stream .*", result['stdout'])
            version = get_version[0].split(":")[1].strip()
            assert StrictVersion("10.6") >= LooseVersion(version)
            log.info("Correct packages are enabled.")
        else:
            log.error(result['stderr'])
            pytest.fail("Failed to verify the packages.")
