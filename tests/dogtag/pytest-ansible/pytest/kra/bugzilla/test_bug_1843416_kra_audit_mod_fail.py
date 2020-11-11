#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Bug 1843416 - kra-audit-mod fail with Invalid event configuration
#               if we have disabled entry in input file
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Deepak Punia <dpunia@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Copyright Red Hat, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""
import os
import sys
import logging
import pytest

try:
    from pki.testlib.common import constants
except Exception:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
audit_file = '/tmp/kra_audit.xml'


def test_bug_1843416_kra_audit_mod_fail(ansible_module):
    """
    :id: 8c929e42-b02e-4bdb-849b-bed941b0aabc
    :Title: Bug 1843416 - kra-audit-mod fail with Invalid event config
    :Description: Bug 1843416 - kra-audit-mod fail with Invalid event configuration if we have disabled entry in input file
    :Requirement: KRA Audit CLI Tests
    :Setup:
        1. Install CA, KRA
    :Steps:
        1. Store audit configuration into xml file using kra-audit-show
        2. Add Stored audit configuration using kra-audit-mod
    :ExpectedResults:
        1. kra-audit-show should store successfully audit configuration into xml
        2. kra-audit-mod should able to add configuration successfully.
    :Automated: Yes
    :CaseComponent: \-
    """
    kra_show = ansible_module.pki(cli='kra-audit-show',
                                  nssdb=constants.NSSDB,
                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                  protocol='https',
                                  port=constants.KRA_HTTPS_PORT,
                                  hostname=constants.MASTER_HOSTNAME,
                                  certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                  extra_args="--output {}".format(audit_file))
    for result in kra_show.values():
        if result['rc'] == 0:
            assert "Stored audit configuration into {}".format(audit_file) in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            pytest.fail()

    kra_mod = ansible_module.pki(cli='kra-audit-mod',
                                 nssdb=constants.NSSDB,
                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                 protocol='https',
                                 port=constants.KRA_HTTPS_PORT,
                                 hostname=constants.MASTER_HOSTNAME,
                                 certnick='"{}"'.format(constants.KRA_ADMIN_NICK),
                                 extra_args="--input {}".format(audit_file))
    for result in kra_mod.values():
        if result['rc'] == 0:
            assert "Modified audit configuration" in result['stdout']
            assert "Invalid event configuration" not in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            pytest.fail()
