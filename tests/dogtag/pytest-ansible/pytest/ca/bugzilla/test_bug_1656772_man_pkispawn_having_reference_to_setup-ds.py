#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   Description: Bug 1656772 -  Update 'man pkispawn' having reference of setup-ds.pl with dscreate command
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   Author: Chandan Pinjani <cpinjani@redhat.com>
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Copyright Red Hat, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""

import sys
import logging
import pytest

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)


@pytest.mark.parametrize('ds_cmd', ['setup-ds.pl', 'dscreate'])
def test_bug_1656772_update_man_pkispawn_with_dscreate(ansible_module, ds_cmd):
    """
    :id: 4d0127e2-d7c6-4c03-9b5b-2b3c4d59fdc4
    :parametrized: yes
    :Title: Bug 1656772 -  Update 'man pkispawn' having reference of setup-ds.pl with dscreate command
    :Description: Bug 1656772 -  Update 'man pkispawn' having reference of setup-ds.pl with dscreate command
    :Requirement: pki server
    :Setup:
        1. Install PKI rpm packages
    :Steps:
        1. Install PKI rpm packages
        2. Refer man pkispawn
    :ExpectedResults:
        1. In RHEL8.0 'setup-ds.pl' command is now replaced with 'dscreate'
        2. The man page should be updated with the command 'dscreate'
    :Automated: Yes
    :CaseComponent: \-
    """
    cmd_out = ansible_module.shell('man pkispawn | grep -i -c "{}"'.format(ds_cmd))
    for result in cmd_out.values():
        if ds_cmd == 'setup-ds.pl':
            if result['rc'] != 0:
                assert result['stdout'] == '0'
                log.info("Successfully checked reference of '{}' in pkispawn man page".format(ds_cmd))
            else:
                log.error(result['stdout'])
                pytest.fail()
        
        if ds_cmd == 'dscreate':
            if result['rc'] == 0:
                assert result['stdout'] != '0'
                log.info("Successfully checked reference of '{}' in pkispawn man page".format(ds_cmd))
            else:
                log.error(result['stdout'])
                pytest.fail()
