#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: No password should be saved in any files after pkispawn
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
import logging
import os
import sys

import pytest

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

topology = int(constants.CA_INSTANCE_NAME.split("-")[-2])

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)


@pytest.mark.skipif('topology != 02')
@pytest.mark.parametrize('subsystem', ['ca', 'kra'])  # TODO remove after build , 'ocsp', 'tks', 'tps'])
def test_bug_1532759_no_passwords_in_file_after_pkispawn(ansible_module, subsystem):
    """
    :Title: No passwords in files after pkispawn of subsystem instances.
            Automation of BZ: 1532759

    :Description: This automation tests if no passwords are
                  stored in any files after pkispawn of subsystem
                   instances.

    :Requirement: RHCS-REQ Installation and Deployment

    :CaseComponent: \-

    :Steps:
            1. Install subsystem instances with passwords under
               DEFAULT section.

    :Expectedresults:
            1. Verify /etc/sysconfig/pki/tomcat/<instance_name>/<subsystem>/deployment.cfg
               has no passwords stored.
            2. The above file should have pkiuser ownership.

    :Automated: Yes
    """
    instance_name = eval('constants.{}_INSTANCE_NAME'.format(subsystem.upper()))
    password = eval('constants.{}_PASSWORD'.format(subsystem.upper()))
    cat_cmd = 'cat /etc/sysconfig/pki/tomcat/{}/{}/deployment.cfg'.format(instance_name, subsystem)
    ls_cmd = 'ls -lrt /etc/sysconfig/pki/tomcat/{}/{}/deployment.cfg'.format(instance_name, subsystem)
    output = ansible_module.shell(cat_cmd)
    for results in output.values():
        if results['rc'] == 0:
            assert password not in results['stdout']
            log.info("No password found in : {}".format(cat_cmd[4:]))
        else:
            log.error("Failed to run: {}".format(results['cmd']))
            pytest.xfail()
    output = ansible_module.shell(ls_cmd)
    for results in output.values():
        if results['rc'] == 0:
            assert 'pkiuser' in results['stdout']
            assert 'root' not in results['stdout']
            log.info("File {} owned by pkiuser".format(cat_cmd[4:]))
        else:
            log.error("Failed to run: {}".format(results['cmd']))
            pytest.xfail()
