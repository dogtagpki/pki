#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Tomcat 8.5 Support in RHEL8
#                Bugzilla: 1596910: Tomcat 8.5 Support
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
import sys
import re
import pytest
from distutils.version import  LooseVersion, StrictVersion

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)


def test_pki_tomcat_packages_should_be_installed(ansible_module):
    """
    :Title: Test pki Tomcat 8.5 package should be installed.
    :Description: Tomcat 8.5 package should be installed in RHEL8
    :Requirement: Tomcat 8.5 Support
    :Setup:
        1. Prepare RHEL8 machine
    :Steps:
        1. Install pki-core module
        2. Install subsystems.
    Expectedresults:
        1. Module get installed successfully
        2. Subsystems should get installed successfully
    :Automated: Yes
    """

    packages = ['pki-servlet-engine', 'pki-ca']

    for package in packages:
        output = ansible_module.command('rpm -qi {}'.format(package))
        for result in output.values():
            if result['rc'] == 0:
                assert 'Name        : {}'.format(package) in result['stdout']
                if package == 'pki-servlet-container':
                    v = re.findall("Version.*", result['stdout'])
                    version = v[0].split(":")[1].strip()
                    assert StrictVersion("8.5") < StrictVersion(version)
                log.info("Package {} successfully installed.".format(package))
            else:
                log.error("Package {} not get installed.".format(package))
                pytest.fail()
