#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   Description: Bug 1584550 - CRMFPopClient: unexpected behavior with -y option when values are specified
#                Bug 1590942 - CMCResponse treats -d as optional
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   Author: Chandan Pinjani <cpinjani@redhat.com>
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


@pytest.mark.parametrize('param', ['-y', ''])
def test_bug_1584550_CRMFPopClient_with_y_option(ansible_module, param):
    """
    :id: 0ef38451-ee72-432f-8acb-a304c1dbee49
    :parametrized: yes
    :Title: Bug 1584550 - CRMFPopClient: unexpected behavior with -y option when values are specified
    :Description: Bug 1584550 - CRMFPopClient: unexpected behavior with -y option when values are specified
    :Requirement: Common CLIs
    :Setup:
        1. Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Install PKI rpm packages and Install CA
        2. Run CRMFPopClient command with -y and without -y option
    :ExpectedResults:
        1. With -y specified, SubjectKeyIdentifier should be visible in command output
        2. Without -y specified, SubjectKeyIdentifier should not be visible in command output
    :Automated: Yes
    :CaseComponent: \-
    """
    cmd = 'CRMFPopClient -d /opt/pki/certdb/ -q POP_SUCCESS -p SECret.123 -o /tmp/cmc_request.csr -n CN=Testing,UID=TEsTinG,O=Test Certificate {} -v -h internal'.format(param)
    log.info("Running command: {}".format(cmd))

    cmd_out = ansible_module.shell(cmd)
    for result in cmd_out.values():
        if param == '-y':
            if result['rc'] == 0:
                assert "Generating SubjectKeyIdentifier extension." in result['stdout']
                log.info("Successfully checked reference of SubjectKeyIdentifier in command output with param {}".format(param))
            else:
                log.error(result['stdout'])
                pytest.fail()
        
        if param == '':
            if result['rc'] == 0:
                assert "Generating SubjectKeyIdentifier extension." not in result['stdout']
                log.info("Successfully checked reference of SubjectKeyIdentifier in command output with no -y param")
            else:
                log.error(result['stdout'])
                pytest.fail()


def test_bug_1590942_CMCResponse_with_d_option(ansible_module):
    """
    :id: 22fe8806-5183-4547-837d-d405a1cc09ea
    :Title: Bug 1590942 - CMCResponse treats -d as optional
    :Description: Bug 1590942 - CMCResponse treats -d as optional
    :Requirement: Common CLIs
    :Setup:
        1. Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Install PKI rpm packages and Install CA
        2. Run PKCS10Client, CMCRequest & HttpClient commands with respective config files
        3. Run CMCResponse with -d option
        4. Run CMCResponse without -d option
    :ExpectedResults:
        1. CMCResponse with -d option should run successfully
        2. CMCResponse without -d option should run successfully
    :Automated: Yes
    :CaseComponent: \-
    """
    cmd_out = ansible_module.shell('PKCS10Client -d {} -p {} -n "cn=test_user, uid=user" -o {}/user.req'.format(constants.NSSDB, constants.CLIENT_DATABASE_PASSWORD, constants.NSSDB))
    for result in cmd_out.values():
        if result['rc'] == 0:
            log.info("Ran PKCS10Client successfully")
        else:
            log.error(result['stderr'])
            pytest.fail()

    cmcrequest_lines = ['numRequests=1', 'input={}/user.req'.format(constants.NSSDB), 'output={}/cmc.user.req'.format(constants.NSSDB), 'tokenname=internal', 'nickname={}'.format(constants.CA_ADMIN_NICK), 'dbdir={}'.format(constants.NSSDB), 'password={}'.format(constants.CLIENT_DATABASE_PASSWORD), 'format=pkcs10']
    for line in cmcrequest_lines:
        ansible_module.lineinfile(path='{}/cmcRequest.cfg'.format(constants.NSSDB), line=line, create='yes')

    cmd_out = ansible_module.shell('CMCRequest {}/cmcRequest.cfg'.format(constants.NSSDB))
    for result in cmd_out.values():
        if result['rc'] == 0:
            log.info("Ran CMCRequest successfully")
        else:
            log.error(result['stderr'])
            pytest.fail()

    httpclient_lines = ['numRequests=1', 'host={}'.format(constants.MASTER_HOSTNAME), 'port={}'.format(constants.CA_HTTPS_PORT), 'secure=true', 'input={}/cmc.user.req'.format(constants.NSSDB), 'output={}/cmc.user.resp'.format(constants.NSSDB),'tokenname=internal', 'dbdir={}'.format(constants.NSSDB), 'clientmode=true', 'password={}'.format(constants.CLIENT_DATABASE_PASSWORD), 'nickname={}'.format(constants.CA_ADMIN_NICK), 'servlet=/ca/ee/ca/profileSubmitCMCFull?profileId=caFullCMCUserCert']
    for line in httpclient_lines:
        ansible_module.lineinfile(path='{}/HttpClient.cfg'.format(constants.NSSDB), line=line, create='yes')

    cmd_out = ansible_module.shell('HttpClient {}/HttpClient.cfg'.format(constants.NSSDB))
    for result in cmd_out.values():
        if result['rc'] == 0:
            log.info("Ran HttpClient successfully")
        else:
            log.error(result['stderr'])
            pytest.fail()

    cmd1 = 'CMCResponse -d {} -i {}/cmc.user.resp'.format(constants.NSSDB, constants.NSSDB)
    log.info("Running command: {}".format(cmd1))

    cmd_out = ansible_module.shell(cmd1)
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Status: SUCCESS" in result['stdout']
            log.info("Successfully ran CMCResponse with -d option")
        else:
            log.error(result['stdout'])
            pytest.fail()

    cmd2 = 'CMCResponse -i {}/cmc.user.resp'.format(constants.NSSDB)
    log.info("Running command: {}".format(cmd2))

    cmd_out = ansible_module.shell(cmd2)
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "Status: SUCCESS" in result['stdout']
            log.info("Successfully ran CMCResponse without -d option")
        else:
            log.error(result['stdout'])
            pytest.fail()
