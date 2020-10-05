"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Automation of bug_1845447: pkispawn fails in FIPS mode:
#                AJP connector has secretRequired="true" but no secret
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
import os
import sys
import time
import pytest
import logging

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
TOPOLOGY = int(constants.CA_INSTANCE_NAME.split("-")[-2])


@pytest.mark.skipif('TOPOLOGY != 0')
def test_pki_bz_1845447_pkispawn_fails_in_fips_mode_ajp_connector_has_secretrequired(ansible_module):
    """
    :Title: Test bz_1845447 pkispawn fails in fips mode ajp connector has secretRequired='true' but no secret
    :Description: pkispawn fails in fips mode ajp connector has secretRequired='true' but no secret
    :Requirement:
    :CaseComponent:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Enable Fips
        2. Install Ldap server
        3. Update pki_ajp_secret=<secret> in CA's [Tomcat] config section
        4. Install the CA subsystem
    :Expected Results:
        1. Installation should be successful
        2. It should add requiredSecret=<secret> in AJP Connector in server.xml
    :Automated: Yes
    """
    # Setup DS instance
    ansible_module.command('cp -R /tmp/test_dir/ /tmp/test_conf')
    log.info('Installing DS')
    out = ansible_module.shell('dscreate from-file /tmp/test_conf/ldap.cfg')
    for result in out.values():
        assert result['rc'] == 0
        log.info("Setup DS instance.")

    # Add pki_ajp_secret= in [Tomcat] of CA config
    log.info('Adding pki_ajp_secret= in [Tomcat]')
    ca_config = '/tmp/test_conf/ca.cfg'
    ansible_module.lineinfile(path=ca_config, line='pki_ajp_secret=TestingPass', insertafter='^pki_tomcat_server_port')

    # Setup CA instance
    log.info('Installing CA')
    install_ca = ansible_module.shell('pkispawn -s CA -f /tmp/test_conf/ca.cfg')
    for result in install_ca.values():
        assert result['rc'] == 0
        log.info("CA Installed successfully")

    # Check the requiredSecret in AJP Connector server.xml
    time.sleep(5)
    log.info('Asserting requiredSecret in AJP Connector server.xml')
    cmd = ansible_module.command('grep -ir requiredSecret /etc/pki/{}/server.xml'.format(constants.CA_INSTANCE_NAME))
    for result in cmd.values():
        if result['rc'] == 0:
            assert 'requiredSecret="TestingPass"' in result['stdout']
            log.info('Successfully found requiredSecret="TestingPass" in AJP Connector server.xml')
        else:
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail('Failed to run : {}'.format(result['cmd']))


@pytest.mark.skipif('TOPOLOGY != 0')
def test_remove_topo00_setup_of_ldap_ca(ansible_module):
    """
        :Title: Remove topology-00 setup of ldap, ca
        :Description: remove setup ldap, ca
        :Requirement:
        :CaseComponent:
        :Setup: Use the subsystems setup in ansible to run subsystem commands
        :Steps:
            1. Destroy CA instance
            2. Remove LDAP server
        :Expected Results:
            1. It should remove all the instance for topo00_setup.
    """
    # Remove CA instance
    log.info('Removing CA')
    remove_ca = ansible_module.shell('pkidestroy -s CA -i {}'.format(constants.CA_INSTANCE_NAME))
    for result in remove_ca.values():
        assert result['rc'] == 0
        log.info("CA removed successfully.")
        time.sleep(5)

    # Remove Ldap server
    log.info('Removing DS')
    remove_ldap = ansible_module.shell('dsctl topology-00-testingmaster remove --do-it')
    for result in remove_ldap.values():
        assert result['rc'] == 0
        log.info("LDAP removed successfully.")
    ansible_module.shell('rm -rf /tmp/test_conf/')
