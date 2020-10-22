#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Common  Supporting functions for configuration &
#   Audit logs
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   This is the library for Common supporting class and Functions.
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Geetika Kapoor <gkapoor@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2019 Red Hat, Inc. All rights reserved.
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
#   Usage:
#   def test_log(ansible_module):
#   	out = get_audit_log(ansible_module, 'kra')
#   	empty_file(ansible_module, out)
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""

try:
    import os
    import ansible
    import logging
    from pytest_ansible import plugin
    from pki.testlib.common.configsetup import AuditLogs, SearchFunctions
    if os.path.isfile('/tmp/test_dir/constants.py'):
        import sys
        sys.path.append('/tmp/test_dir')
        import constants
except:
    raise

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)

def empty_file(ansible_module, filename):
    '''
    This function is used for making file empty so that logs can be searched easily without any issues
    :param filename:file to be cleanedup
    :return:no return value
    '''
    log.info("File to be cleaned up : {}".format(filename))
    ansible_module.command("truncate -s 0 {}".format(filename))

def identify_path(subsystem):
    subsystem_all = {'ca': constants.CA_INSTANCE_NAME , 'kra': constants.KRA_INSTANCE_NAME,
                     'ocsp': constants.OCSP_INSTANCE_NAME, 'tks': constants.TKS_INSTANCE_NAME,
                     'tps': constants.TPS_INSTANCE_NAME}
    subsystem_normalize = {k.lower(): v for k, v in subsystem_all.items()}
    if subsystem.lower() in subsystem_normalize:
        instanceout =  subsystem_normalize[subsystem.lower()]
    pki_cs_cfg = constants.PKI_CS_FILE
    pki_cs_cfg = pki_cs_cfg.replace("instance", instanceout)
    pki_cs_cfg = pki_cs_cfg.replace("subsystem", subsystem.lower())
    return pki_cs_cfg, instanceout

def get_audit_log(ansible_module, subsystem):
    """
    :param ansible_modules:
    :return:return location of audit file
    Note: We have not used lookup module by ansible instead of grep because lookup
    can't be done on remote environment.Lookup's are meant for source machine .
    we have not used configparser as well because that can't be run remotely
    also there are changes in configparser functionality in python3 and that
    can cause problems so we go with command and grep.
    """
    cs_config = identify_path(subsystem)[0]
    output = ansible_module.command('grep SignedAudit.fileName {}'.format(cs_config))
    log.info(output)
    assert SearchFunctions().assertOutputHelper(output,'rc') == 0, 'Incorrect output:{}'.format(output)
    audit_file = SearchFunctions().assertOutputHelper(output).split("=")[1]
    log.info(" Path for Audit logs : {}".format(audit_file))
    return audit_file

def get_debug_log(ansible_module, subsystem):
    """
    :param ansible_modules:
    :return: location of debug logs
    Refer : https://www.dogtagpki.org/wiki/PKI_10.7_Server_Debug_Log
    By default log messages will be stored in /var/log/pki/pki-tomcat/<subsystem>/debug.YYYY-MM-DD.log
    These changes are only applicable for debug logs for log rotation
    """
    cs_config = identify_path(subsystem)[0]
    instance = identify_path(subsystem)[1]
    output = ansible_module.command('grep debug.filename {}'.format(cs_config))
    log.info(output)
    if SearchFunctions().assertOutputHelper(output, 'rc') != 0:
        date = ansible_module.command("date '+%Y-%m-%d'")
        debug_file = '/var/log/pki/{}/{}/debug.{}.log'.\
            format(instance, subsystem, SearchFunctions().assertOutputHelper(date))
    else:
        debug_file = SearchFunctions().assertOutputHelper(output).split("=")[1]
    log.info(" Path for Debug logs : {}".format(debug_file))
    return debug_file

def get_system_log(ansible_module, subsystem):
    """
    :param ansible_modules:
    :return: return location of system logs
    """
    cs_config = identify_path(subsystem)[0]
    output = ansible_module.command('grep System.fileName {}'.format(cs_config))
    assert SearchFunctions().assertOutputHelper(output,'rc') == 0, 'Incorrect output:{}'.format(output)
    system_file = SearchFunctions().assertOutputHelper(output).split("=")[1]
    log.info(" Path for System logs : {}".format(system_file))
    return system_file


def get_selftest_log(ansible_module, subsystem):
    """
    :param ansible_modules:
    :return:return location of selftest logs
    """
    cs_config = identify_path(subsystem)[0]
    output = ansible_module.command('grep selftests.container.logger.fileName {}'.format(cs_config))
    assert SearchFunctions().assertOutputHelper(output,'rc') == 0, 'Incorrect output:{}'.format(output)
    selftest_file = SearchFunctions().assertOutputHelper(output).split("=")[1]
    log.info(" Path for selftest logs : {}".format(selftest_file))
    return selftest_file

def get_transactions_log(ansible_module, subsystem):
    """
    :param ansible_modules:
    :return: return location of transactions log
    """
    cs_config = identify_path(subsystem)[0]
    output = ansible_module.command('grep Transactions.fileName {}'.format(cs_config))
    assert SearchFunctions().assertOutputHelper(output,'rc') == 0, 'Incorrect output:{}'.format(output)
    transactions_file = SearchFunctions().assertOutputHelper(output).split("=")[1]
    log.info(" Path for transactions logs : {}".format(transactions_file))
    return transactions_file
