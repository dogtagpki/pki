#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Bug 1874595 - TPS - Server side key generation is not working for Identity only tokens
#
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
import time, datetime

try:
    from pki.testlib.common import constants
except Exception:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
date = str(datetime.date.today())

ldap_path = "/tmp/test_dir/ldap_user_add.cfg"
format_path = '/tmp/test_dir/token_format.txt'
enroll_path = '/tmp/test_dir/token_enroll.txt'


def test_bug_1539198_inconsistent_cert_req_outcomes(ansible_module):
    """
    :id: b153b08d-7525-46a4-8346-29691b471dab
    :Title: Bug 1874595 - TPS - Server side key generation is not working
    :Description: Bug 1874595 - TPS - Server side key generation is not working for Identity only tokens
    :Requirement: tps bugzilla
    :Setup:
        1. Install CA, KRA, OCSP, TKS and TPS
    :Steps:
        1. Set debug.level=0 in TPS CS.cfg restart TPS
        2. Perform format and enrollment with default userKey
        3. format/delete token
        4. edit tps CS.cfg change op.enroll.userKey.keyGen.encryption.serverKeygen.enable=false and restart tps
        5. format and enroll the token again
    :Expectedresults:
        1. All debug log should generate
        2. debug log should have "final serverkegGen enabled? true"
        3. token should be formated
        4. new value should be set op.enroll.userKey.keyGen.encryption.serverKeygen.enable=false
        5. debug log should have final serverkegGen enabled? false

    :Automated: Yes
    :CaseComponent: \-
    """
    # Change tps debug log level
    cmd_out = ansible_module.shell("pki-server tps-config-set debug.level 0 -i {}".format(constants.TPS_INSTANCE_NAME))
    for result in cmd_out.values():
        if result['rc'] == 0:
            log.info("Successfully ran : {}".format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
    ansible_module.shell("pki-server restart {}".format(constants.TPS_INSTANCE_NAME))
    time.sleep(10)

    # Add ldap user for tps operation
    ldap_user_out = ansible_module.shell('ldapadd -h {} -p {} -D "cn=Directory Manager" -w {} -f {}'
                                         ''.format(constants.MASTER_HOSTNAME, constants.LDAP_PORT,
                                                   constants.LDAP_PASSWD,
                                                   ldap_path))
    for result in ldap_user_out.values():
        if result['rc'] == 0:
            log.info("Successfully ran : '{}'".format(result['cmd']))
        else:
            log.info("Failed to ran : '{}'".format(result['cmd']))
            pytest.fail()

    log.info("Format tpsclient token")
    ansible_module.shell('tpsclient < {}'.format(format_path))
    time.sleep(5)

    # Enroll tps token
    log.info("Enroll tpsclient token")
    ansible_module.shell('tpsclient < {}'.format(enroll_path))
    time.sleep(10)

    log_cmd = "tail -n 1000 /var/log/pki/{}/tps/debug.{}.log".format(constants.TPS_INSTANCE_NAME, date)
    log_result = ansible_module.command(log_cmd)
    for result in log_result.values():
        if result['rc'] == 0:
            assert "final serverkegGen enabled? true" in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            pytest.fail()

    ansible_module.shell('tpsclient < {}'.format(format_path))
    time.sleep(5)

    ansible_module.replace(path="/var/lib/pki/{}/tps/conf/CS.cfg".format(constants.TPS_INSTANCE_NAME),
                           regexp="op.enroll.userKey.keyGen.encryption.serverKeygen.enable=.*",
                           replace="op.enroll.userKey.keyGen.encryption.serverKeygen.enable=false")
    ansible_module.shell("pki-server restart {}".format(constants.TPS_INSTANCE_NAME))
    time.sleep(10)

    log.info("Format tpsclient token")
    ansible_module.shell('tpsclient < {}'.format(format_path))
    time.sleep(5)

    # Enroll tps token
    log.info("Enroll tpsclient token")
    ansible_module.shell('tpsclient < {}'.format(enroll_path))
    time.sleep(10)

    log_cmd = "tail -n 1000 /var/log/pki/{}/tps/debug.{}.log".format(constants.TPS_INSTANCE_NAME, date)
    log_result = ansible_module.command(log_cmd)
    for result in log_result.values():
        if result['rc'] == 0:
            assert "FINE: TKSRemoteRequestHandler: computeSessionKey():  " \
                   "final serverkegGen enabled? false" in result['stdout']
            log.info("Successfully run : {}".format(result['cmd']))
        else:
            log.error("Failed to run : {}".format(result['cmd']))
            pytest.fail()
