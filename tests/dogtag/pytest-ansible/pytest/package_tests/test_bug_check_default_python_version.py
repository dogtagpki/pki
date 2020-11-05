#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Check default python version for RHEL 8
#                Bug: 1596897 Port Dogtag to Python 3
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
import sys
import pytest

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)


def test_checkdefaultpythonversion(ansible_module):
    """
    :id: c95e9530-15de-489b-a931-415c2e822ae7
    :Title: Bug - Port Dogtag to Python 3
    :Description: Bug 1596897 Port Dogtag to Python 3
    :Requirement: Python3 Support
    :Setup:
        1. Install pki-core packages
    :Steps:
        1. Check default python version is Python 3
    :ExpectedResults:
        1. Default python version should be Python 3
    :Automated: Yes
    """
    cmd = ansible_module.command('cat /etc/redhat-release')
    for result in cmd.values():
        if 'Fedora' in result['stdout']:
            check_default_py_version = ansible_module.command("python3 --version")
            for result in check_default_py_version.values():
                if result['rc'] == 0:
                    assert "Python 3.8" in result['stdout']
                    log.info('Successfully Found python 3.8.* version')
                else:
                    log.error(result['stdout'])
                    log.error(result['stderr'])

        elif 'Red Hat' in result['stdout']:
            check_default_py_version = ansible_module.command("/usr/libexec/platform-python --version")
            for result in check_default_py_version.values():
                if result['rc'] == 0:
                    assert "Python 3.6" in result['stdout']
                    log.info('Successfully Found python 3.6.* version')
                else:
                    log.error(result['stdout'])
                    log.error(result['stderr'])
                    pytest.fail()
        else:
            log.error('Unable to find the right OS variant')
            pytest.fail()
