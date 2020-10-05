#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Bug 1565073 - The log file located at
#                /var/log/pki/pki-tomcat/ca/debug is growing and not
#                getting rotated on all IPA servers
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


try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

def test_rotate_log_files(ansible_module):
    """
    :id: a01e9166-378b-4dc7-88cc-13f01753ee37

    :Title: Bug - Rotate log files

    :Description: Bug 1565073 - The log file located at
                  /var/log/pki/pki-tomcat/ca/debug is growing and not
                  getting rotated on all IPA servers

    :Requirement: Installation and Deployment

    :Setup:
        1. Setup dogtag PKI using ansible playbooks

    :Steps:
        1. Setup Dogtag PKI CA
        2. Observe CA debug log at /var/log/pki/pki-tomcat/ca/debug.YYYY-MM-DD.log.
        3. Stop CA
        4. Advance system date
        5. Restart CA
        6. Perform any CA operation

    :Expectedresults:
        1. CA should be setup successfully
        2. CA debug log entries should be populated
        3. CA should be shutdown successfully
        4. System date should be advanced successfully
        5. CA should restart successfully
        6. CA operation should show up in the newly created log file with the advanced system date

    :Automated: No

    """
