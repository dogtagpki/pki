#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: pki-server  status with nuxwdog enabled - BZ1732981automation
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
##
#   Author: Shalini Khandelwal <skhandel@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2020 Red Hat, Inc. All rights reserved.
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
import os
import sys
import re

from utils import NuxwdogOperations

import pytest

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)

subsystem_dict = {'CA': constants.CA_INSTANCE_NAME, 'KRA': constants.KRA_INSTANCE_NAME,
                  'OCSP': constants.OCSP_INSTANCE_NAME, 'TKS': constants.TKS_INSTANCE_NAME,
                  'TPS': constants.TPS_INSTANCE_NAME}


@pytest.mark.parametrize("subsystem_arg", ["CA", "KRA", "OCSP", "TKS", "TPS"])
def test_bug_1732981_pkiserver_status_with_nuxwdog_enable(subsystem_arg, ansible_module):
    """
    :id: 264d13e3-5e54-4c3b-9b9b-d3042f2b1e80
    :parametrized: yes
    :Title: Bug 1732981 - When nuxwdog is enabled pkidaemon (pki-server) status shows instances as stopped.
    :Requirement: Installation and Deployment
    :Description: This automation tests functioning of pki-server status when CA instance is nuxwdog enabled
    :Setup: Have all the required packages installed with 5 subsystems installed (topo-01 or topo-02 installed)
    :Steps:
            1. Enable nuxwdog on CA instance
            2. Check status of running instance using pkidaemon status
    :Expectedresults:
            1. Instance should be successfully nuxwdog enabled.
            2. pki-server status should show the instance in running state.
            3. pki-server status should show KRA instance as nuxwdpg enable false and instance status as ACTIVE.
    :Automated: Yes
    :CaseComponent: \-
    """
    if '01' in constants.CA_INSTANCE_NAME:
        subsystem_name = 'pki-tomcat'
        password_conf = '/etc/pki/{}/password.conf'
        if subsystem_arg != 'CA':
            pytest.skip("For shared tomcat installation all the subsystems are installed under one pki-tomcat instance."
                        "Thus skipping this test for {} subsystem".format (subsystem_arg))
    else:
        subsystem_name = subsystem_dict[subsystem_arg]
        password_conf = '/var/lib/pki/{}/conf/password.conf'

    nuxwdog_obj = NuxwdogOperations(ansible_module, subsystem_type=subsystem_arg,
                                    subsystem_name=subsystem_name, password_conf=password_conf)
    nuxwdog_obj.enable_nuxwdog()
    nuxwdog_obj.pkiserver_nuxwdog()

    # Disbale nuxwdog at the end of test.
    nuxwdog_obj.disable_nuxwdog()

    # Todo : RHEL 8.4 https://bugzilla.redhat.com/show_bug.cgi?id=1732981#c10
    #  https://github.com/dogtagpki/pki/pull/515

    # # Additional test for non enabled subsystem. It should show status as false and running.
    # # This is executed with first test, when CA subsystem is only nuxwdog enabled
    # if subsystem_arg == 'CA' and ('01' not in constants.CA_INSTANCE_NAME):
    #     for subsystem in subsystem_dict.values():
    #         if subsystem != constants.CA_INSTANCE_NAME:
    #             output = ansible_module.shell('pki-server status {}'.format(subsystem))
    #             for result in output.values():
    #                 assert re.search("Instance ID:\s+{}".format(subsystem), result['stdout'])
    #                 assert re.search("Active:\s+True", result['stdout'])
    #                 assert re.search("Enabled:\s+True", result['stdout'])
    #                 assert re.search("Nuxwdog Enabled:\s+False", result['stdout'])
