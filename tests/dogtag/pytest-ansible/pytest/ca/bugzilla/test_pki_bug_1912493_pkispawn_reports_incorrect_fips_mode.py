#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   Description: Bug 1912493 - pkispawn reports incorrect FIPS mode
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   Author: Pritam Singh <prisingh@redhat.com>
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Copyright Red Hat, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""

import sys
import os
import logging
import pytest

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)

if os.path.isfile('/tmp/test_dir/constants.py'):
    import sys
    sys.path.append('/tmp/test_dir')
    import constants


def test_pki_bug_1912493_pkispawn_reports_incorrect_fips_mode(ansible_module):
    """
    :id: 5d111451-82d3-4d39-91e9-d6a464e8c53d
    :Title: Bug 1912493 - pkispawn reports incorrect FIPS mode
    :Description: pkispawn generates 'INFO: FIPS Mode: True' even if the FIPS mode is not enabled on the machine
    :Requirement: Installation and Deployment
    :Setup:
        1. Install PKI rpm packages
    :Steps:
        1. Install PKI rpm packages
        2. pkispawn CA with --debug param
        3. Assert the 'INFO: FIPS Mode: False'
    :ExpectedResults:
        1. FIPS disabled machine should generate 'INFO: FIPS Mode: False' in spawn log
        2. FIPS enabled machine should report the 'INFO: FIPS Mode: True'
    :Automated: Yes
    :CaseComponent: \-
    """

    # Install DS
    cmd = 'dscreate from-file /tmp/test_dir/ldap.cfg'
    cmd_out = ansible_module.command(cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Completed installation' in result['stdout']
            log.info('Successfully Installed DS')
        else:
            log.error('Failed to install DS')
            pytest.fail()

    # Install CA
    cmd_out = ansible_module.command('pkispawn -s CA -f /tmp/test_dir/ca.cfg --debug')
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'INFO: FIPS mode: False' in result['stderr']
            log.info('Successfully found the correct FIPS mode')
        else:
            log.error('Failed to install CA')
            pytest.fail()

    # Remove the CA
    cmd_out = ansible_module.command('pkidestroy -s CA -i {} --remove-logs'.format(constants.CA_INSTANCE_NAME))
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Uninstallation complete.' in result['stdout']
            log.info('Successfully removed the CA')
        else:
            log.error('Failed to remove CA')
            pytest.fail()

    # Remove the DS
    cmd_out = ansible_module.command('dsctl topology-00-testingmaster remove --do-it')
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert 'Completed instance removal' in result['stdout']
            log.info('Successfully removed the DS')
        else:
            log.error('Failed to remove DS')
            pytest.fail()
