#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: CONFIG_ROLE audit message should not have line breaks.
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Roshni Pattath <rpattath@redhat.com>
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

import pytest

def test_bug_1595606_audit_message_config_role(ansible_module, subsystem):

    """
    :Title: CONFIG_ROLE audit message should not have line breaks.
            Automation of BZ: 1532759

    :Description: This automation tests CONFIG_ROLE audit messages
                  does not have line breaks and audit verify succeeds.

    :Requirement: RHCS-REQ Installation and Deployment

    :CaseComponent: \-

    :Steps:
            1. Install subsystem instances.
            2. Add a role user.
            3. Add a user certificate to the role user

    :Expectedresults:
            1. No line breaks in CONFIG_ROLE audit message when cert 
               is added
            2. AuditVerify of the audit log should succeed.

    :Automated: No
    """
