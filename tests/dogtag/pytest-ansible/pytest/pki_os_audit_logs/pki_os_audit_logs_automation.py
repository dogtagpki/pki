"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Enabling OS-level Audit Logs
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   Enabling OS-level Audit Logs
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Sneha Veeranki <sveerank@redhat.com>
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

import pytest
import logging
import os
import sys
import time
import ansible

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)


@pytest.mark.parametrize('service_name', e)
def test_restart_auditd(ansible_module, service_name):
    ansible_module.command("service {} restart".format(service_name))


def test_audit_enable_log_deletion(ansible_module):
    """
        :id: 0e5b1515-4d4b-4cb7-81f4-301e187e1474
        :Title: Test Auditing Certificate System Audit Log Deletions.
        :Description: Test Auditing Certificate System Audit Log Deletions. Refer https://access.redhat.com/documentation/en-us/
        red_hat_certificate_system/9/html-single/planning_installation_and_deployment_guide_common_criteria_edition/
        index#operating_system_external_to_rhcs_log_settings
        :Requirement: PKI OS level audit logs
        :Setup: Use the subsystems setup in ansible to run subsystem commands
        :Steps:
            1. Add a new file to generate audit logs for the Certificate System Audit Log Deletions.
        :ExpectedResults:
            1. Upon write, append, execute operations, audit logs are generated.
    """
    ansible_module.yum(name="audit", state='present')
    ansible_module.file(path="/etc/audit/rules.d/rhcs-audit-log-deletion.rules", state="touch")
    ansible_module.lineinfile(path="/etc/audit/rules.d/rhcs-audit-log-deletion.rules",
                              line='-a always,exit -F arch=b32 -S unlink -F dir=/var/log/pki -F key=rhcs_audit_deletion \n'
                                   '-a always,exit -F arch=b32 -S rename -F dir=/var/log/pki -F key=rhcs_audit_deletion \n'
                                   '-a always,exit -F arch=b32 -S rmdir -F dir=/var/log/pki -F key=rhcs_audit_deletion \n'
                                   '-a always,exit -F arch=b32 -S unlinkat -F dir=/var/log/pki -F key=rhcs_audit_deletion \n'
                                   '-a always,exit -F arch=b32 -S renameat -F dir=/var/log/pki -F key=rhcs_audit_deletion \n'
                                   '-a always,exit -F arch=b64 -S unlink -F dir=/var/log/pki -F key=rhcs_audit_deletion \n'
                                   '-a always,exit -F arch=b64 -S rename -F dir=/var/log/pki -F key=rhcs_audit_deletion \n'
                                   '-a always,exit -F arch=b64 -S rmdir -F dir=/var/log/pki -F key=rhcs_audit_deletion \n'
                                   '-a always,exit -F arch=b64 -S unlinkat -F dir=/var/log/pki -F key=rhcs_audit_deletion \n'
                                   '-a always,exit -F arch=b64 -S renameat -F dir=/var/log/pki -F key=rhcs_audit_deletion')
    test_restart_auditd(ansible_module, "auditd")


@pytest.mark.parametrize("subsystem", [constants.CA_INSTANCE_NAME, constants.KRA_INSTANCE_NAME,
                                       constants.OCSP_INSTANCE_NAME, constants.TKS_INSTANCE_NAME,
                                       constants.TPS_INSTANCE_NAME])
def test_audit_verify_log_deletion(ansible_module, subsystem):
    """
        :id: e1d29425-c6a0-4873-97a8-b0f0e3be5c40
        :Title: Test Auditing Certificate System Audit Log Deletions.
        :Description: Test Auditing Certificate System Audit Log Deletions.
        :Requirement: PKI OS level audit logs
        :Setup: Use the subsystems setup in ansible to run subsystem commands
        :Steps:
        1. Delete all the subsystems' manager log files.
        2. Check if the audit logs contain the modifications.
        :ExpectedResults:
        1. ausearch is a simple command line tool used to search the audit daemon log files based on events.
        2. Check if ausearch --interpret -k rhcs_audit_deletion gives detailed audit messages.
    """
    # Delete a log file
    searchResults = ansible_module.find(path="/var/log/pki/{}/".format(subsystem), patterns="manager.*")
    for file in searchResults.values()[0].get("files"):
        filePath = file.get("path")
        print(filePath)
        ansible_module.file(path="{}".format(filePath), state="absent")
    cmd_out = ansible_module.raw("ausearch --interpret -k rhcs_audit_deletion")
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "name=/var/log/pki/{}".format(subsystem) in result['stdout']
            assert "DELETE" in result['stdout']
            assert "uid=root gid=root" in result['stdout']
            assert "key=rhcs_audit_deletion" in result['stdout']
            log.info('Successfully ran : {}'.format(cmd_out))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
    ansible_module.file(path="/etc/audit/rules.d/rhcs-audit-log-deletion.rules", state="absent")


def test_audit_enable_time_change_event(ansible_module):
    """
        :id: 835107b6-f402-4e7b-b089-e405176de14e
        :Title: Test Auditing Certificate System Auditing Time Change Events.
        :Description: Test Auditing Certificate System Auditing Time Change Events. Refer https://access.redhat.com/documentation/en-us/
        red_hat_certificate_system/9/html-single/planning_installation_and_deployment_guide_common_criteria_edition/
        index#operating_system_external_to_rhcs_log_settings
        :Requirement: PKI OS level audit logs
        :Setup: Use the subsystems setup in ansible to run subsystem commands
        :Steps:
            1. Add a new file to generate audit logs for the Certificate System Auditing Time Change Events.
        :ExpectedResults:
            1. Upon performing time change operations, audit logs are generated.
    """
    ansible_module.file(path="/etc/audit/rules.d/rhcs-audit-rhcs_audit_time_change.rules", state="touch")
    ansible_module.lineinfile(path="/etc/audit/rules.d/rhcs-audit-rhcs_audit_time_change.rules",
                              line='-a always,exit -F arch=b32 -S adjtimex,settimeofday,stime -F key=rhcs_audit_time_change \n'
                                   '-a always,exit -F arch=b64 -S adjtimex,settimeofday -F key=rhcs_audit_time_change \n'
                                   '-a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -F key=rhcs_audit_time_change \n'
                                   '-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -F key=rhcs_audit_time_change \n'
                                   '-a always,exit -F arch=b32 -S clock_adjtime -F key=rhcs_audit_time_change \n'
                                   '-a always,exit -F arch=b64 -S clock_adjtime -F key=rhcs_audit_time_change \n'
                                   '-w /etc/localtime -p wa -k rhcs_audit_time_change \n')
    test_restart_auditd(ansible_module, "auditd")


def test_audit_verify_time_change_event(ansible_module):
    """
        :id: c2ee349d-077a-404a-95fc-8c08ef1ac195
        :Title: Test Auditing Certificate System Auditing Time Change Events.
        :Description: Test Auditing Certificate System Auditing Time Change Events.
        :Requirement: PKI OS level audit logs
        :Setup: Use the subsystems setup in ansible to run subsystem commands
        :Steps:
            1. Modify the system date:
            2. Check if the audit logs contain the modifications.
        :ExpectedResults:
        1. ausearch is a simple command line tool used to search the audit daemon log files based on events.
        2. Check if ausearch --interpret -k rhcs_audit_time_change gives detailed audit messages.
    """
    # Change date
    ansible_module.shell("date -s yesterday;")
    ansible_module.shell("date -s tomorrow;")
    cmd_out = ansible_module.raw("ausearch --interpret -k rhcs_audit_time_change")
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "proctitle=date -s yesterday" in result['stdout']
            assert "proctitle=date -s tomorrow" in result['stdout']
            assert "a0=CLOCK_REALTIME" in result['stdout']
            assert "uid=root gid=root" in result['stdout']
            assert "key=rhcs_audit_time_change" in result['stdout']
            log.info('Successfully ran : {}'.format(cmd_out))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
    ansible_module.file(path="/etc/audit/rules.d/rhcs-audit-rhcs_audit_time_change.rules", state="absent")


def test_audit_enable_nssdb(ansible_module):
    """
        :id: 97e26dbf-d1de-43c4-9181-81723e65c8ff
        :Title: Test Auditing Unauthorized Certificate System Use of Secret Keys.
        :Description: Test Auditing Unauthorized Certificate System Use of Secret Keys. Refer https://access.redhat.com/documentation/en-us/
        red_hat_certificate_system/9/html-single/planning_installation_and_deployment_guide_common_criteria_edition/
        index#operating_system_external_to_rhcs_log_settings
        :Requirement: PKI OS level audit logs
        :Setup: Use the subsystems setup in ansible to run subsystem commands
        :Steps:
            1. Add a new file to generate audit logs for the Unauthorized Certificate System Use of Secret Keys.
        :ExpectedResults:
            1. Upon unauthorized Certificate System use of secret keys, audit logs are generated.
    """
    file_path = ["/etc/pki/{}/".format(constants.CA_INSTANCE_NAME), "/etc/pki/{}/".format(constants.KRA_INSTANCE_NAME),
                 "/etc/pki/{}/".format(constants.OCSP_INSTANCE_NAME),
                 "/etc/pki/{}/".format(constants.TKS_INSTANCE_NAME),
                 "/etc/pki/{}/".format(constants.TPS_INSTANCE_NAME), ]
    file_name = ["alias", "alias/cert8.db", "alias/cert9.db", "alias/key3.db",
                 "alias/key4.db", "alias/secmod.db", "alias/pkcs11.txt"]
    ansible_module.file(path="/etc/audit/rules.d/rhcs-audit-nssdb-access.rules", state="touch")
    for a in file_path:
        for b in file_name:
            ansible_module.lineinfile(path="/etc/audit/rules.d/rhcs-audit-nssdb-access.rules",
                                      line='-w {}{} -p warx -k rhcs_audit_nssdb'.format(a, b))
    test_restart_auditd(ansible_module, "auditd")


@pytest.mark.parametrize("subsystem", [constants.CA_INSTANCE_NAME, constants.KRA_INSTANCE_NAME,
                                       constants.OCSP_INSTANCE_NAME, constants.TKS_INSTANCE_NAME,
                                       constants.TPS_INSTANCE_NAME])
def test_audit_certutil_nssdb(ansible_module, subsystem):
    """
        :id: e0c7a466-f8b9-4dd5-8b9b-9b318938a53d
        :Title: Test Auditing Unauthorized Certificate System Use of Secret Keys.
        :Description: Test Auditing Unauthorized Certificate System Use of Secret Keys.
        :Requirement: PKI OS level audit logs
        :Setup: Use the subsystems setup in ansible to run subsystem commands
        :Steps:
            1. Add a new file to generate audit logs for the Unauthorized Certificate System Use of Secret Keys.
            2. Check if the audit logs contain the events.
        :ExpectedResults:
            1. ausearch is a simple command line tool used to search the audit daemon log files based on events.
            2. Check if ausearch --interpret -k rhcs_audit_nssdb gives detailed audit messages.
    """
    # List the certs and keys
    ansible_module.shell("certutil -L -d /etc/pki/{}/alias".format(subsystem))
    cmd_out = ansible_module.raw("ausearch --interpret -k rhcs_audit_nssdb")
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "proctitle=certutil -L -d /etc/pki/{}/alias".format(subsystem) in result['stdout']
            assert "O_RDONLY" in result['stdout']
            assert "uid=root gid=root" in result['stdout']
            assert "key=rhcs_audit_nssdb" in result['stdout']
            log.info('Successfully ran : {}'.format(cmd_out))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


@pytest.mark.parametrize("subsystem", [constants.CA_INSTANCE_NAME, constants.KRA_INSTANCE_NAME,
                                       constants.OCSP_INSTANCE_NAME, constants.TKS_INSTANCE_NAME,
                                       constants.TPS_INSTANCE_NAME])
def test_audit_restart_server(ansible_module, subsystem):
    """
        :id: 63672b27-ac85-49cc-a6ab-9f5191d3b383
        :Title: Test Auditing Unauthorized Certificate System Use of Secret Keys.
        :Description: Test Auditing Unauthorized Certificate System Use of Secret Keys. Refer https://access.redhat.com/documentation/en-us/
        red_hat_certificate_system/9/html-single/planning_installation_and_deployment_guide_common_criteria_edition/
        index#operating_system_external_to_rhcs_log_settings
        :Requirement: PKI OS level audit logs
        :Setup: Use the subsystems setup in ansible to run subsystem commands
        :Steps:
            1. Add a new file to generate audit logs for the Unauthorized Certificate System Use of Secret Keys.
            2. Check if the audit logs contain the events.
        :ExpectedResults:
            1. ausearch is a simple command line tool used to search the audit daemon log files based on events.
            2. Check if ausearch --interpret -k rhcs_audit_nssdb gives detailed audit messages.
    """
    # List the certs and keys
    ansible_module.shell("systemctl restart pki-tomcatd@{}".format(subsystem))
    time.sleep(20)
    cmd_out = ansible_module.raw("ausearch --interpret -k rhcs_audit_nssdb")
    time.sleep(20)
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "name=/etc/pki/{}/alias/pkcs11.txt".format(subsystem) in result['stdout']
            assert "O_RDONLY" in result['stdout']
            assert "key=rhcs_audit_nssdb" in result['stdout']
            assert "uid=root gid=root" in result['stdout']
            log.info('Successfully ran : {}'.format(cmd_out))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
    ansible_module.file(path="/etc/audit/rules.d/rhcs-audit-nssdb-access.rules", state="absent")


@pytest.mark.parametrize("subsystem, type_subsystem",
                         [(constants.CA_INSTANCE_NAME, 'ca'), (constants.KRA_INSTANCE_NAME, 'kra'),
                          (constants.OCSP_INSTANCE_NAME, 'ocsp'), (constants.TKS_INSTANCE_NAME, 'tks'),
                          (constants.TPS_INSTANCE_NAME, 'tps')])
def test_audit_enable_config_file(ansible_module, subsystem, type_subsystem):
    """
        :id: 249f589a-b298-4fa9-8717-c99aaef99ed4
        :Title: Test Auditing Certificate System CS.cfg and server.xml file modification.
        :Description: Test Auditing Certificate System CS.cfg and server.xml file modification. Refer https://access.redhat.com/documentation/en-us/
        red_hat_certificate_system/9/html-single/planning_installation_and_deployment_guide_common_criteria_edition/
        index#operating_system_external_to_rhcs_log_settings
        :Requirement: PKI OS level audit logs
        :Setup: Use the subsystems setup in ansible to run subsystem commands
        :Steps:
            1. Add a new file to generate audit logs for the Certificate System Configuration.
        :ExpectedResults:
            1. Upon audit log file deletions, audit logs are generated.
    """
    file_path = ["/etc/pki/{}/".format(constants.CA_INSTANCE_NAME), "/etc/pki/{}/".format(constants.KRA_INSTANCE_NAME),
                 "/etc/pki/{}/".format(constants.OCSP_INSTANCE_NAME),
                 "/etc/pki/{}/".format(constants.TKS_INSTANCE_NAME), "/etc/pki/{}/".format(constants.TPS_INSTANCE_NAME)]
    file_name = ["CS.cfg", "server.xml"]
    ansible_module.file(path="/etc/audit/rules.d/rhcs-audit-config-access.rules", state="touch")
    for file_path in file_path:
        for file_name in file_name:
            if file_name == "CS.cfg":
                path = "/etc/pki/{}/{}".format(subsystem, type_subsystem)
                ansible_module.lineinfile(path="/etc/audit/rules.d/rhcs-audit-config-access.rules",
                                          line="-w {}/{} -p wax -k rhcs_audit_config".format(path, file_name))
            elif file_name == "server.xml":
                path = "/etc/pki/{}".format(subsystem)
                ansible_module.lineinfile(path="/etc/audit/rules.d/rhcs-audit-config-access.rules",
                                          line="-w {}/{} -p wax -k rhcs_audit_config".format(path, file_name))
    test_restart_auditd(ansible_module, "auditd")


@pytest.mark.parametrize("subsystem",
                         [constants.CA_INSTANCE_NAME, constants.KRA_INSTANCE_NAME,
                          constants.OCSP_INSTANCE_NAME,
                          constants.TKS_INSTANCE_NAME, constants.TPS_INSTANCE_NAME])
def test_audit_modify_server_xml(ansible_module, subsystem):
    """
    :id: 7efda1e1-09c9-4684-906d-0758717c3511
    :Title: Test Auditing Certificate System server.xml file modification.
    :Description: Test Auditing Certificate System server.xml file modification.
    :Requirement: PKI OS level audit logs
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Modify all the subsystems' server.xml files
        2. Check if the audit logs contain the modifications.
    :ExpectedResults:
        1. ausearch is a simple command line tool used to search the audit daemon log files based on events.
        2. Check if ausearch --interpret -k rhcs_audit_config gives detailed audit messages.
    """
    # Modify server.xml file
    ansible_module.lineinfile(path="/etc/pki/{}/server.xml".format(subsystem),
                              line="#Test the audit messages for server.xml")
    ansible_module.lineinfile(path="/etc/pki/{}/server.xml".format(subsystem), line="#Test the audit messages for server.xml",
                              state="absent")
    cmd_out = ansible_module.raw("ausearch --interpret -k rhcs_audit_config")
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "name=/etc/pki/{}".format(subsystem) in result['stdout']
            assert "uid=root gid=root" in result['stdout']
            assert "key=rhcs_audit_config" in result['stdout']
            log.info('Successfully ran : {}'.format(cmd_out))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


@pytest.mark.parametrize("subsystem, type_subsystem",
                         [(constants.CA_INSTANCE_NAME, '/ca/CS.cfg'), (constants.KRA_INSTANCE_NAME, '/kra/CS.cfg'),
                          (constants.OCSP_INSTANCE_NAME, '/ocsp/CS.cfg'),
                          (constants.TKS_INSTANCE_NAME, '/tks/CS.cfg'), (constants.TPS_INSTANCE_NAME, '/tps/CS.cfg')])
def test_audit_modify_config(ansible_module, subsystem, type_subsystem):
    """
    :id: b31ebfd1-5d52-4f33-b70d-e7eb70652e67
    :Title: Test Auditing Certificate System CS.cfg file modification.
    :Description: Test Auditing Certificate System CS.cfg file modification.
    :Requirement: PKI OS level audit logs
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Modify all the subsystems' CS.cfg files
        2. Check if the audit logs contain the modifications.
    :ExpectedResults:
        1. ausearch is a simple command line tool used to search the audit daemon log files based on events.
        2. Check if ausearch --interpret -k rhcs_audit_config gives detailed audit messages.
    """
    # Modify CS.cfg file
    ansible_module.lineinfile(path="/etc/pki/{}{}".format(subsystem, type_subsystem),
                              line="#Test the audit messages for CS.cfg")
    ansible_module.lineinfile(path="/etc/pki/{}{}".format(subsystem, type_subsystem), line="#Test the audit messages for CS.cfg",
                              state="absent")
    cmd_out = ansible_module.raw("ausearch --interpret -k rhcs_audit_config")
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert "name=/etc/pki/{}".format(subsystem) in result['stdout']
            assert "uid=root gid=root" in result['stdout']
            assert "key=rhcs_audit_config" in result['stdout']
            log.info('Successfully ran : {}'.format(cmd_out))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()
    ansible_module.file(path="/etc/audit/rules.d/rhcs-audit-config-access.rules", state="absent")
