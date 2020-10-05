"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI HEALTH CHECK TOOL AUTOMATION
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki-healthcheck cli commands needs to be tested:
#   pki-healthcheck
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Pritam Singh <prisingh@redhat.com>
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

from pki.testlib.common.certlib import sys, os
import re
import pytest
import time

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)

sources = ['pki.server.healthcheck.meta.csconfig', 'pki.server.healthcheck.meta.connectivity',
           'pki.server.healthcheck.certs.expiration', 'pki.server.healthcheck.certs.trustflags']

dogtag_checks = ['CASystemCertExpiryCheck', 'CASystemCertTrustFlagCheck', 'CADogtagCertsConfigCheck',
                 'DogtagCACertsConnectivityCheck', 'KRASystemCertExpiryCheck', 'KRASystemCertTrustFlagCheck',
                 'KRADogtagCertsConfigCheck', 'DogtagKRAConnectivityCheck', 'OCSPSystemCertExpiryCheck',
                 'OCSPSystemCertTrustFlagCheck', 'OCSPDogtagCertsConfigCheck', 'DogtagOCSPConnectivityCheck',
                 'TKSSystemCertExpiryCheck', 'TKSSystemCertTrustFlagCheck', 'TKSDogtagCertsConfigCheck',
                 'DogtagTKSConnectivityCheck', 'TPSSystemCertExpiryCheck', 'TPSSystemCertTrustFlagCheck',
                 'TPSDogtagCertsConfigCheck', 'DogtagTPSConnectivityCheck']

ca_config = ['"/var/lib/pki/pki-tomcat/ca/conf/CS.cfg"']
kra_config = ['"/var/lib/pki/pki-tomcat/kra/conf/CS.cfg"']
ocsp_config = ['"/var/lib/pki/pki-tomcat/ocsp/conf/CS.cfg"']
tks_config = ['"/var/lib/pki/pki-tomcat/tks/conf/CS.cfg"']
tps_config = ['"/var/lib/pki/pki-tomcat/tps/conf/CS.cfg"']

directives = [
    'ca.signing.cert',
    'ca.sslserver.cert',
    'ca.ocsp_signing.cert',
    'ca.subsystem.cert',
    'ca.audit_signing.cert',
    'kra.transport.cert',
    'kra.storage.cert',
    'kra.audit_signing.cert'
]
ca_cfg_path = '/var/lib/pki/pki-tomcat/conf/ca/CS.cfg'


def fix_certificate(ansible_module):
    command = ansible_module.shell('grep ca.signing.certnickname= {}'.format(ca_cfg_path))
    for result in command.values():
        find_ca_cert_param = re.findall(r"ca.signing.certnickname=[\w].*", result['stdout'])
        for i in find_ca_cert_param:
            ca_signing_cert = i.split("=")[1].strip()
            ca_cert = 'ca.signing.nickname=' + ca_signing_cert
            ansible_module.lineinfile(path=ca_cfg_path, regexp='^ca.signing.nickname=', line=ca_cert)


def test_pki_health_check_with_help_param(ansible_module):
    """
    :id: 41f51dd9-2146-4ad4-bacf-e63ed7fdba97
    :Title: Test pki-healhcheck --help command
    :Description: test pki-healthcheck --help command
    :Requirement: PKI health check tool to display the health status of all the PKI subsytems
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Testing pki-healthcheck command with --help
    :Expected results:
        1. It should return help message.
    :Automated: Yes
    """
    cmd = ansible_module.command('pki-healthcheck --help')
    for result in cmd.values():
        if result['rc'] == 0:
            assert 'usage: pki-healthcheck' in result['stdout']
            log.info('Successfully ran: {}'.format(result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail('Failed to run: {}'.format(result['cmd']))


def test_pki_health_check_command(ansible_module):
    """
    :id: cb149fea-5975-41bf-bf2c-b09a6cb65347
    :Title: Test pki-healhcheck
    :Description: test pki-healthcheck command
    :Requirement: PKI health check tool to display the health status of all the PKI subsytems
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Testing pki-healthcheck command
    :Expected results:
        1. It should return result of pki health
    :Automated: Yes
    """
    check_list = []
    source_list = []
    cmd = 'pki-healthcheck'
    cmd_out = ansible_module.command(cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:

            # Assert checks
            chk = list(set(re.findall('"check":.*', result['stdout'])))
            for i in chk:
                check_list.append(re.split(r'[:,"\s]\s*', i)[4])
            for check in dogtag_checks:
                if check in dogtag_checks:
                    assert check in check_list
                    log.info("Found {} in {}".format(check, result['cmd']))
                else:
                    log.error('Not found {} in {}'.format(check, result['stdout']))
                    log.error(result['stderr'])
                    pytest.fail()

            # Assert source
            source = list(set(re.findall('"source":.*', result['stdout'])))
            for i in source:
                source_list.append(re.split(r'[:,"\s]\s*', i)[4])
            for source in sources:
                if source in sources:
                    assert source in source_list
                    log.info("Found {} in {}".format(source, result['cmd']))
                else:
                    log.error('Not found {} in {}'.format(source, result['stdout']))
                    log.error(result['stderr'])
                    pytest.fail()

            # Assert config files of subsystems
            for ca in ca_config:
                assert '"configfile": {}'.format(ca) in result['stdout']
                log.info('Successfully found CA configuration file')
            for kra in kra_config:
                assert '"configfile": {}'.format(kra) in result['stdout']
                log.info('Successfully found KRA configuration file')
            for ocsp in ocsp_config:
                assert '"configfile": {}'.format(ocsp) in result['stdout']
                log.info('Successfully found OCSP configuration file')
            for tks in tks_config:
                assert '"configfile": {}'.format(tks) in result['stdout']
                log.info('Successfully found TKS configuration file')
            for tps in tps_config:
                assert '"configfile": {}'.format(tps) in result['stdout']
                log.info('Successfully found TPS configuration file')
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail('Failed to run: {}'.format(result['cmd']))


def test_pki_health_check_with_list_sources_param(ansible_module):
    """
    :id: 28819437-269e-4048-ac34-555be7d47b09
    :Title: Test pki-healhcheck --list-sources command
    :Description: test pki-healthcheck --list-sources command
    :Requirement: PKI health check tool to display the health status of all the PKI subsytems
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Testing pki-healthcheck command with --list-sources
    :Expected results:
        1. It should return the source and checks of health check tool.
    :Automated: Yes
    """
    cmd = 'pki-healthcheck  --list-sources'
    cmd_out = ansible_module.command(cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            for check in dogtag_checks:
                assert check in result['stdout']
                log.info('Found {} in {}'.format(check, result['cmd']))
            for source in sources:
                assert source in result['stdout']
                log.info('Found {} in {}'.format(source, result['cmd']))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail('Failed to run: {}'.format(result['cmd']))


def test_pki_health_check_with_source_param(ansible_module):
    """
    :id: ff80bf90-f29e-4105-9a86-c29016ec48c0
    :Title: Test pki-healhcheck --source command
    :Description: test pki-healthcheck --source command
    :Requirement: PKI health check tool to display the health status of all the PKI subsytems
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Testing pki-healthcheck command with --source <SOURCE>
    :Expected results:
        1. It should return the result for param as --source <source>
    :Automated: Yes
    """
    check_list = []
    source_list = []
    for source in sources:
        cmd = 'pki-healthcheck --source {}'.format(source)
        cmd_out = ansible_module.command(cmd)
        for result in cmd_out.values():
            if result['rc'] == 0:

                # Assert checks
                chk = list(set(re.findall('"check":.*', result['stdout'])))
                for i in chk:
                    check_list.append(re.split(r'[:,"\s]\s*', i)[4])
                for check in check_list:
                    if check in check_list:
                        assert check in dogtag_checks
                        log.info("Found {} in {}".format(check, result['cmd']))
                    else:
                        log.error('Not found {} in {}'.format(check, result['stdout']))
                        log.error(result['stderr'])
                        pytest.fail()

                # Assert source
                source = list(set(re.findall('"source":.*', result['stdout'])))
                for i in source:
                    source_list.append(re.split(r'[:,"\s]\s*', i)[4])
                for s in source_list:
                    if s in source_list:
                        assert s in sources
                        log.info("Found {} in {}".format(s, result['cmd']))
                    else:
                        log.error('Not found {} in {}'.format(s, result['stdout']))
                        log.error(result['stderr'])
                        pytest.fail()

            else:
                log.error(result['stdout'])
                log.error(result['stderr'])
                pytest.fail('Failed to run: {}'.format(result['cmd']))


def test_pki_health_check_with_source_and_check_param(ansible_module):
    """
    :id: ad09f7d2-6ed9-4c0a-9dd9-b38e8fd08903
    :Title: Test pki-healhcheck --source <source> --check <check> command
    :Description: test pki-healthcheck --source <source> --check <check> command
    :Requirement: PKI health check tool to display the health status of all the PKI subsytems
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Testing pki-healthcheck command with --source <SOURCE> --check <CHECK>
    :Expected results:
        1. It should return the result based on source and check.
    :Automated: Yes
    """
    for source in sources:
        for chk in dogtag_checks:
            cmd = 'pki-healthcheck --source {} --check {}'.format(source, chk)
            cmd_out = ansible_module.command(cmd)
            for result in cmd_out.values():
                if result['rc'] == 0:

                    # Assert checks
                    chek = re.search('"check":(.*),', result['stdout'])
                    assert re.split(r'[:,"\s]\s*', chek.group(1))[2] in dogtag_checks
                    log.info('Successfully found: "{}" check'.format(chek.group(1).strip()))

                    # Assert source
                    src = re.search('"source":(.*),', result['stdout'])
                    assert re.split(r'[:,"\s]\s*', src.group(1))[2] in sources
                    log.info('Successfully found: "{}" source'.format(src.group(1).strip()))

                else:
                    assert result['rc'] == 1
                    assert "Check '{}' not found in Source '{}'".format(chk, source)
                    pass


@pytest.mark.parametrize('ot', ['human', 'json'])
def test_pki_health_check_with_output_type_param_as_human_and_json(ansible_module, ot):
    """
    :id: bb61e40c-24c6-4ade-b87c-a3ee8064283d
    :parametrized: yes
    :Title: Test pki-healhcheck --output-type human/json command
    :Description: test pki-healthcheck --output-type human/json command
    :Requirement: PKI health check tool to display the health status of all the PKI subsytems
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Testing pki-healthcheck command with --output-type human
        2. Testing pki-healthcheck command with --output-type json
    :Expected results:
        1. It should return the result in human and json readable format
    :Automated: Yes
    """
    check_list = []
    source_list = []
    cmd = 'pki-healthcheck --output-type {}'.format(ot)
    cmd_out = ansible_module.command(cmd)
    for result in cmd_out.values():
        if ot == 'human':
            if result['rc'] == 0:

                # Assert source.check.key in result['stdout']
                assert 'SUCCESS: {}.{}'.format(sources[2], dogtag_checks[0]) in result['stdout']
                log.info('Successfully found {}+"."+{} in {}'.format(sources[2], dogtag_checks[0], result['cmd']))
            else:
                log.error(result['stderr'])
                log.error(result['stdout'])
                pytest.fail("Failed to run: {}".format(result['cmd']))
        elif ot == 'json':
            if result['rc'] == 0:

                # Assert checks
                chk = list(set(re.findall('"check":.*', result['stdout'])))
                for i in chk:
                    check_list.append(re.split(r'[:,"\s]\s*', i)[4])
                for check in dogtag_checks:
                    if check in dogtag_checks:
                        assert check in check_list
                        log.info("Found {} in {}".format(check, result['cmd']))
                    else:
                        log.error('Not found {} in {}'.format(check, result['stdout']))
                        log.error(result['stderr'])
                        pytest.fail()

                # Assert source
                source = list(set(re.findall('"source":.*', result['stdout'])))
                for i in source:
                    source_list.append(re.split(r'[:,"\s]\s*', i)[4])
                for source in sources:
                    if source in sources:
                        assert source in source_list
                        log.info("Found {} in {}".format(source, result['cmd']))
                    else:
                        log.error('Not found {} in {}'.format(source, result['stdout']))
                        log.error(result['stderr'])
                        pytest.fail()

                # Assert config files of subsystems
                for ca in ca_config:
                    assert '"configfile": {}'.format(ca) in result['stdout']
                    log.info('Successfully found CA configuration file')
                for kra in kra_config:
                    assert '"configfile": {}'.format(kra) in result['stdout']
                    log.info('Successfully found KRA configuration file')
                for ocsp in ocsp_config:
                    assert '"configfile": {}'.format(ocsp) in result['stdout']
                    log.info('Successfully found OCSP configuration file')
                for tks in tks_config:
                    assert '"configfile": {}'.format(tks) in result['stdout']
                    log.info('Successfully found TKS configuration file')
                for tps in tps_config:
                    assert '"configfile": {}'.format(tps) in result['stdout']
                    log.info('Successfully found TPS configuration file')
            else:
                log.error(result['stdout'])
                log.error(result['stderr'])
                pytest.fail('Failed to run: {}'.format(result['cmd']))


def test_pki_health_check_with_output_file_param(ansible_module):
    """
    :id: c11b1edf-5e45-4ff1-a137-436b226831dd
    :Title: Test pki-healhcheck --output-file <OUTFILE> command
    :Description: test pki-healthcheck --output-file <OUTFILE> command
    :Requirement: PKI health check tool to display the health status of all the PKI subsytems
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Testing pki-healthcheck command with --output-file /tmp/data
    :Expected results:
        1. It should export the data in json format to /tmp/data file.
    :Automated: Yes
    """
    path = '/tmp/data'
    cmd = 'pki-healthcheck --output-file {}'.format(path)
    cmd_out = ansible_module.command(cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            assert result['rc'] == 0
            is_file = ansible_module.stat(path=path)
            for r1 in is_file.values():
                assert r1['stat']['exists']
                log.info('Successfully file exported at {}'.format(path))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()


def test_pki_health_check_with_input_file_param(ansible_module):
    """
    :id: 6e9e6703-9b3f-43b0-a090-76b7e6f55c3d
    :Title: Test pki-healhcheck --input-file <INFILE> command
    :Description: test pki-healthcheck --input-file <INFILE> command
    :Requirement: PKI health check tool to display the health status of all the PKI subsytems
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Testing pki-healthcheck command with --input-file /tmp/data
    :Expected results:
        1. It should import the data and can be readable to the user.
    :Automated: Yes
    """
    check_list = []
    source_list = []
    path = '/tmp/data'
    cmd = 'pki-healthcheck --input-file {}'.format(path)
    cmd_out = ansible_module.command(cmd)
    for result in cmd_out.values():
        if result['rc'] > 0:

            # Assert result i.e SUCCESS
            rst = re.search('"result":(.*),', result['stdout'])
            assert 'SUCCESS' in re.split(r'[:,"\s]\s*', rst.group(1))[2]
            log.info('Successfully found: "{}" result'.format(rst.group(1).strip()))

            # Assert checks
            chk = list(set(re.findall('"check":.*', result['stdout'])))
            for i in chk:
                check_list.append(re.split(r'[:,"\s]\s*', i)[4])
            for check in dogtag_checks:
                if check in dogtag_checks:
                    assert check in check_list
                    log.info("Found {} in {}".format(check, result['cmd']))
                else:
                    log.error('Not found {} in {}'.format(check, result['stdout']))
                    log.error(result['stderr'])
                    pytest.fail()

            # Assert source
            source = list(set(re.findall('"source":.*', result['stdout'])))
            for i in source:
                source_list.append(re.split(r'[:,"\s]\s*', i)[4])
            for source in sources:
                if source in sources:
                    assert source in source_list
                    log.info("Found {} in {}".format(source, result['cmd']))
                else:
                    log.error('Not found {} in {}'.format(source, result['stdout']))
                    log.error(result['stderr'])
                    pytest.fail()

            # Assert config files of subsystems
            for ca in ca_config:
                assert '"configfile": {}'.format(ca) in result['stdout']
                log.info('Successfully found CA configuration file')
            for kra in kra_config:
                assert '"configfile": {}'.format(kra) in result['stdout']
                log.info('Successfully found KRA configuration file')
            for ocsp in ocsp_config:
                assert '"configfile": {}'.format(ocsp) in result['stdout']
                log.info('Successfully found OCSP configuration file')
            for tks in tks_config:
                assert '"configfile": {}'.format(tks) in result['stdout']
                log.info('Successfully found TKS configuration file')
            for tps in tps_config:
                assert '"configfile": {}'.format(tps) in result['stdout']
                log.info('Successfully found TPS configuration file')
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail('Failed to run: {}'.format(result['cmd']))


def test_pki_health_check_with_failures_only_param_for_csconfig_check(ansible_module):
    """
    :id: b712e933-92e5-468a-a494-270223730879
    :Title: Test pki-healhcheck --failures-only command
    :Description: test pki-healthcheck --failures-only command
    :Requirement: PKI health check tool to display the health status of all the PKI subsytems
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Testing pki-healthcheck command with --failures-only command
    :Expected results:
        1. It should return the failure result.
    :Automated: Yes
    """
    # This add's bogus cert in ca.signing.nickname
    ansible_module.lineinfile(path=ca_cfg_path, regexp='^ca.signing.nickname=',
                              line="ca.signing.nickname=Bogus casigningCert")
    cmd = 'pki-healthcheck --failures-only'
    cmd_out = ansible_module.command(cmd)
    for result in cmd_out.values():
        if result['rc'] > 0:

            # Assert result i.e ERROR
            rst = re.search('"result":(.*),', result['stdout'])
            assert 'ERROR' in re.split(r'[:,"\s]\s*', rst.group(1))[2]
            log.info('Successfully found: "{}" result'.format(rst.group(1).strip()))

            # Assert directives
            dir_name = re.search('"directive":(.*),', result['stdout'])
            assert re.split(r'[:,"\s]\s*', dir_name.group(1))[2] in directives
            log.info('Successfully found: "{}" result'.format(dir_name.group(1).strip()))
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail('Failed to run: {}'.format(result['cmd']))

    fix_certificate(ansible_module)  # This will fix the ca signing cert
    time.sleep(2)


def test_pki_health_check_with_failures_only_param_for_connectivity_check(ansible_module):
    """
    :id: 774cd43f-04af-4698-b5cf-d4faae3b760f
    :Title: Test pki-healhcheck --failures-only command
    :Description: test pki-healthcheck --failures-only command
    :Requirement: PKI health check tool to display the health status of all the PKI subsytems
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Testing pki-healthcheck command with --failures-only command
    :Expected results:
        1. It should return the failure result.
    :Automated: Yes
    """
    # Stop DS
    ds_instance = 'topology-01-testingmaster'
    cmd = ansible_module.command('dsctl {} stop'.format(ds_instance))
    for result in cmd.values():
        if result['rc'] == 0:
            assert 'Instance "{}" has been stopped'.format(ds_instance) in result['stdout']
            log.info('Successfully Stop the DS server')
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail('Failed to Stop DS server')

    # Run pki-healthcheck with --failures-only
    cmd = 'pki-healthcheck --failures-only'
    cmd_out = ansible_module.command(cmd)
    for result in cmd_out.values():
        if result['rc'] > 0:
            assert 'Internal server error Unable to search for certificates' in result['stderr']
            log.info('Successfully ran: {}'.format(result['cmd']))
        else:
            pytest.fail('Failed to run: {}'.format(result['cmd']))

    # Start DS
    ds_instance = 'topology-01-testingmaster'
    cmd = ansible_module.command('dsctl {} start'.format(ds_instance))
    for result in cmd.values():
        if result['rc'] == 0:
            assert 'Instance "{}" has been started'.format(ds_instance) in result['stdout']
            log.info('Successfully Stop the DS server')
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail('Failed to Start DS server')

    # Validate pki-healthcheck --failures-only
    time.sleep(5)
    cmd = 'pki-healthcheck --failures-only'
    cmd_out = ansible_module.command(cmd)
    for result in cmd_out.values():
        if result['rc'] == 0:
            log.info('Successfully ran: {}'.format(result['cmd']))
        else:
            pytest.fail('Failed to run: {}'.format(result['cmd']))


@pytest.mark.parametrize('severity', ['SUCCESS', 'ERROR', 'CRITICAL'])
def test_pki_health_check_with_severity_param(ansible_module, severity):
    """
    :id: 1d31259c-6a09-4e54-8d79-1357aeb81b81
    :parametrized: yes
    :Title: Test pki-healhcheck --severity {'CRITICAL', 'SUCCESS', 'ERROR'} command
    :Description: test pki-healthcheck --severity {'CRITICAL', 'SUCCESS', 'ERROR'} command
    :Requirement: PKI health check tool to display the health status of all the PKI subsytems
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Testing pki-healthcheck command with --severity {'CRITICAL', 'SUCCESS', 'ERROR'}
    :Expected results:
        1. It should return the result as different status {'CRITICAL', 'SUCCESS', 'ERROR'}.
    :Automated: Yes
    """
    check_list = []
    source_list = []
    cmd = 'pki-healthcheck --severity "{}"'.format(severity)
    cmd_out = ansible_module.command(cmd)
    for result in cmd_out.values():
        if severity == 'SUCCESS':
            if result['rc'] == 0:

                # Assert result i.e SUCCESS
                rst = re.search('"result":(.*),', result['stdout'])
                assert 'SUCCESS' in re.split(r'[:,"\s]\s*', rst.group(1))[2]
                log.info('Successfully found: "{}" result'.format(rst.group(1).strip()))

                # Assert checks
                chk = list(set(re.findall('"check":.*', result['stdout'])))
                for i in chk:
                    check_list.append(re.split(r'[:,"\s]\s*', i)[4])
                for check in dogtag_checks:
                    if check in dogtag_checks:
                        assert check in check_list
                        log.info("Found {} in {}".format(check, result['cmd']))
                    else:
                        log.error('Not found {} in {}'.format(check, result['stdout']))
                        log.error(result['stderr'])
                        pytest.fail()

                # Assert source
                source = list(set(re.findall('"source":.*', result['stdout'])))
                for i in source:
                    source_list.append(re.split(r'[:,"\s]\s*', i)[4])
                for source in sources:
                    if source in sources:
                        assert source in source_list
                        log.info("Found {} in {}".format(source, result['cmd']))
                    else:
                        log.error('Not found {} in {}'.format(source, result['stdout']))
                        log.error(result['stderr'])
                        pytest.fail()

                # Assert config files of subsystems
                for ca in ca_config:
                    assert '"configfile": {}'.format(ca) in result['stdout']
                    log.info('Successfully found CA configuration file')
                for kra in kra_config:
                    assert '"configfile": {}'.format(kra) in result['stdout']
                    log.info('Successfully found KRA configuration file')
                for ocsp in ocsp_config:
                    assert '"configfile": {}'.format(ocsp) in result['stdout']
                    log.info('Successfully found OCSP configuration file')
                for tks in tks_config:
                    assert '"configfile": {}'.format(tks) in result['stdout']
                    log.info('Successfully found TKS configuration file')
                for tps in tps_config:
                    assert '"configfile": {}'.format(tps) in result['stdout']
                    log.info('Successfully found TPS configuration file')
            else:
                log.error(result['stdout'])
                log.error(result['stderr'])
                pytest.fail('Failed to run: {}'.format(result['cmd']))

            # This add's bogus cert which allows healthcheck to throw ERROR
            ansible_module.lineinfile(path=ca_cfg_path, regexp='^ca.signing.nickname=',
                                      line="ca.signing.nickname=Bogus casigningCert")
        elif severity == 'ERROR':
            if result['rc'] > 0:

                # Assert result i.e ERROR
                rst = re.search('"result":(.*),', result['stdout'])
                assert 'ERROR' in re.split(r'[:,"\s]\s*', rst.group(1))[2]
                log.info('Successfully found: "{}" result'.format(rst.group(1).strip()))

                # Assert directives
                dir_name = re.search('"directive":(.*),', result['stdout'])
                assert re.split(r'[:,"\s]\s*', dir_name.group(1))[2] in directives
                log.info('Successfully found: "{}" result'.format(dir_name.group(1).strip()))
            else:
                log.error(result['stdout'])
                log.error(result['stderr'])
                pytest.fail('Failed to run: {}'.format(result['cmd']))

            # This will fix the ca signing cert nickname
            fix_certificate(ansible_module)
            time.sleep(2)

            # This will rename the pki tomcat config file which allows the trigger the 'CRITICAL' status
            ansible_module.command('mv /usr/share/pki/etc/tomcat.conf /usr/share/pki/etc/tomcat.conf.bk')
            time.sleep(2)

        elif severity == 'CRITICAL':
            if result['rc'] > 0:

                # Assert result i.e CRITICAL
                rst = re.search('"result":(.*),', result['stdout'])
                assert 'CRITICAL' in re.split(r'[:,"\s]\s*', rst.group(1))[2]
                log.info('Successfully found: "{}" result'.format(rst.group(1).strip()))
            else:
                log.error(result['stdout'])
                log.error(result['stderr'])
                pytest.fail('Failed to run: {}'.format(result['cmd']))

            # Fix pki tomcat config
            ansible_module.command('mv /usr/share/pki/etc/tomcat.conf.bk /usr/share/pki/etc/tomcat.conf')

    # Remove the exported file
    ansible_module.command('rm -rf /tmp/data')
