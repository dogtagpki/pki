#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Bug 1614839 - CC: Enable all config audit events
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


def test_bug_enable_all_config_audit_events():
    """
    :Title: Bug - CC: Enable all config audit events

    :Description: Bug - CC: Enable all config audit events

    :Requirement:

    :Setup:
        1. Setup DS
        2. Setup DogtagPKI

    :Steps:
        1. Disable caUserCert profile
           pki -d /tmp/nssdb/ -c SECret.123 -n CA_AgentV ca-profile-disable caUserCert
        2. Enable caUserCert profile
           pki -d /tmp/nssdb/ -c SECret.123 -n CA_AgentV ca-profile-enable caUserCert
        3. Start pkiconsole
           GoTo Certificate Manager-> CRL Issuing Point -> Master CRL -> Format
           click on the Revocation List Signing Algorithm drop-down list
        4. Add and LDAP user, Configure UidPwdDirAuth in pkiconsole, Goto EE page
           select caDirUserCert profile

    :Expectedresults:
        1. caUserCert profile should be successfully disabled
           Audit log should show the following entry
           [AuditEvent=CERT_PROFILE_APPROVAL][SubjectID=CA_AgentV][Outcome=Success]
           [ProfileID=caUserCert][Op=disapprove] certificate profile approval
        2. caUserCert profile should be successfully enabled
           [AuditEvent=CERT_PROFILE_APPROVAL][SubjectID=CA_AgentV][Outcome=Success]
           [ProfileID=caUserCert][Op=approve] certificate profile approval
        3. MD2 or MD5 algorithms should no be listed in the drop down
        4. RSA should be shown in the drop list of algorithms

    :Automated: No

    :CaseComponent: \-
    """
