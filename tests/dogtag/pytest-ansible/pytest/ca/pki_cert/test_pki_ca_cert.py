#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI USER-CERT CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki user commands needs to be tested:
#   pki user-cert
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Amol Kahat <akahat@redhat.com>
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


@pytest.mark.parametrize('cmd',('', '--help'))
def test_pki_cert(ansible_module, cmd):
    """
    :id: 90dc81fe-17af-477d-9a82-34808c2b86c5
    :Title: Test pki cert with '' and --help message.
    :Description: Test pki cert with ' ' and --help message.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Run pki cert with ''
        2. Run pki cert with --help
    :Expectedresults:
        1. It should show help message.
        2. It should show help message.
    """
    command = 'pki cert %s' % (cmd)
    output = ansible_module.command(command)
    for host, result in output.items():
        assert "Commands:" in result['stdout']
        assert "cert-find            Find certificates" in result['stdout']
        assert "cert-show            Show certificate" in result['stdout']
        assert "cert-revoke          Revoke certificate" in result['stdout']
        assert "cert-hold            Place certificate on-hold" in result['stdout']
        assert "cert-release-hold    Place certificate off-hold" in result['stdout']
        assert "cert-request-find    Find certificate requests" in result['stdout']
        assert "cert-request-show    Show certificate request" in result['stdout']
        assert "cert-request-submit  Submit certificate request" in result['stdout']
        assert "cert-request-review  Review certificate request" in result['stdout']
        assert "cert-request-profile-find List Enrollment templates" in result['stdout']
        assert "cert-request-profile-show Get Enrollment template" in result['stdout']


@pytest.mark.parametrize('cmd',('', '--help'))
def test_pki_cert(ansible_module, cmd):
    """
    :Title: Test pki ca-cert with '' and --help message.
    :Description: Test pki ca-cert with ' ' and --help message.
    :Requirement: RHCS-REQ Certificate Authority Certificate Enrollment
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Run pki ca-cert with ''
        2. Run pki ca-cert with --help
    :Expectedresults:
        1. It should show help message.
        2. It should show help message.
    """
    command = 'pki ca-cert %s' % (cmd)
    output = ansible_module.command(command)
    for host, result in output.items():
        assert "Commands:" in result['stdout']
        assert "ca-cert-find            Find certificates" in result['stdout']
        assert "ca-cert-show            Show certificate" in result['stdout']
        assert "ca-cert-revoke          Revoke certificate" in result['stdout']
        assert "ca-cert-hold            Place certificate on-hold" in result['stdout']
        assert "ca-cert-release-hold    Place certificate off-hold" in result['stdout']
        assert "ca-cert-request-find    Find certificate requests" in result['stdout']
        assert "ca-cert-request-show    Show certificate request" in result['stdout']
        assert "ca-cert-request-submit  Submit certificate request" in result['stdout']
        assert "ca-cert-request-review  Review certificate request" in result['stdout']
        assert "ca-cert-request-profile-find List Enrollment templates" in result['stdout']
        assert "ca-cert-request-profile-show Get Enrollment template" in result['stdout']
