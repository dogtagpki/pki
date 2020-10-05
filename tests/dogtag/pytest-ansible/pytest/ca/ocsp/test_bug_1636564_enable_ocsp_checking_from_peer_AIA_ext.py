"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Automation of Bug_1636564_enable_ocsp_checking_from_peer_AIA_ext
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Pritam Singh <prisingh@redhat.com>
#   Author: Amol Kahat <akahat@redhat.com>
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
import re
import datetime
import time
import sys
import tempfile

import pytest

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

temp_dir = tempfile.mkdtemp(suffix="_test", prefix='profile_', dir="/tmp/")
kra_server_xml = os.path.join(temp_dir, '/server.xml')
log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
TOPOLOGY = constants.CA_INSTANCE_NAME.split("-")[-2]

if TOPOLOGY == '01':
    instance = "pki-tomcat"
else:
    instance = constants.CA_INSTANCE_NAME

BASE_DIR = '/var/lib/pki/'
ca_cfg_path = BASE_DIR + '/' + instance + '/' + 'ca/conf/CS.cfg'


def test_topo00_setup_for_ldap_ca_and_kra(ansible_module):
    """
    :Title: Topology-00 setup for ldap, ca & kra
    :Description: setup ldap, ca & kra
    :Requirement:
    :CaseComponent:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Install Ldap server
        2. Install CA
        3. Install KRA
    :Expected Results:
        1. It should install ldap, ca & kra.
    """
    # Setup DS instance
    ansible_module.command('cp -R /tmp/test_dir/ /tmp/test_conf')
    out = ansible_module.shell('dscreate from-file /tmp/test_conf/ldap.cfg')
    for result in out.values():
        assert result['rc'] == 0
        log.info("Setup DS instance.")

    # Setup CA instance
    install_ca = ansible_module.shell('pkispawn -s CA -f /tmp/test_conf/ca.cfg')
    for result in install_ca.values():
        assert result['rc'] == 0
        log.info("CA Installed successfully")


def restart_instance(ansible_module):
    command = 'pki-server restart {}'.format(instance)
    out = ansible_module.shell(command)
    for res in out.values():
        assert res['rc'] == 0


# Change debug.level=0 in CA's CS.cfg
def test_setup(ansible_module):
    ansible_module.lineinfile(path=ca_cfg_path, regexp="debug.level=10", line="debug.level=0")
    restart_instance(ansible_module)
    log.info("Restarted instance : {}".format(instance))
    time.sleep(10)

    # Modify kra config
    kra_conf = '/tmp/test_conf/kra.cfg'
    cert_chain = '/var/lib/pki/{}/alias/ca.crt'.format(instance)
    ansible_module.lineinfile(path=kra_conf, regexp='^pki_cert_chain_path=',
                              line='pki_cert_chain_path={}'.format(cert_chain))

    # Setup KRA instance
    time.sleep(10)
    install_kra = ansible_module.shell('pkispawn -s KRA -f /tmp/test_conf/kra.cfg')
    for result in install_kra.values():
        time.sleep(5)
        assert result['rc'] == 0
        log.info("KRA installed successfully")


def test_bug_1636564_cc_tomcatjss_unable_to_enable_ocsp(ansible_module):
    """
    :Title: Test Bug 1636564 CC Tomcatjss unable to enable ocsp checking from peer AIA extension
    :Description: Tomcatjss lack to check its peer's AIA extension instead of the default url set in server.xml.
    :Requirement:
    :CaseComponent:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Check for AIA Extension on KRA subsystem cert
    :ExpectedResults:
        1. It will return all the KRA's cert which has AIA extension.

    """
    INTERNAL_OCSP_URI = 'http://{}:{}/ca/ocsp'.format(constants.MASTER_HOSTNAME,
                                                      constants.CA_HTTP_PORT)
    internal_pass_file = '/tmp/internal_pass.txt'
    aia_regex = "Name\:\sAuthority\sInformation\sAccess.*\n.*\n.*Location.*\n.*.\n.*"
    instance_db = '/var/lib/pki/{}/alias'.format(constants.KRA_INSTANCE_NAME)
    grep_internal_password = "grep 'internal=' /var/lib/pki/{}/conf/password.conf | cut -d'=' -f2 > {}".format(
        constants.KRA_INSTANCE_NAME, internal_pass_file)
    ansible_module.shell(grep_internal_password)
    find_kra_certs = 'pki -d {} -C {} client-cert-find'.format(instance_db, internal_pass_file)
    cert_names = []
    find_certs = ansible_module.shell(find_kra_certs)
    for result in find_certs.values():
        if result['rc'] == 0:
            nick_list = re.findall("Nickname:.*", result['stdout'])
            for i in nick_list:
                cert_names.append(i.split(":")[1].strip())
        else:
            log.error("Failed to find the certificate nicks")
            log.error("Failed to run: {}".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    for nick in cert_names:
        certutil_cmd = 'certutil -L -d {} -n "{}"'.format(instance_db, nick)
        certutil_out = ansible_module.shell(certutil_cmd)
        for res in certutil_out.values():
            if res['rc'] == 0:
                aia_ext = re.findall(aia_regex, res['stdout'])
                for k in aia_ext:
                    try:
                        assert INTERNAL_OCSP_URI in k
                        log.info("Found internal OCSP URI on cert: '{}'".format(nick))
                    except Exception as e:
                        print(e)
                        log.error("AIA extension not found for cert : {}".format(nick))
                        pytest.fail()
            else:
                log.error("AIA extension not found for cert : {}".format(nick))
                pytest.fail()


def test_verify_cert_serial_number_for_kra_from_ca_debug_log(ansible_module):
    """
    :Title: Test Force KRA to check for Internal OCSP URI in CA's debug log
    :Description: Test Force KRA to check for Internal OCSP URI in CA's debug log
    :Requirement:
    :CaseComponent:
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Stop the KRA instance
        2. Modify the changes -
            2.1 Copy the server.xml to /tmp/
            2.2 Make changes to server.xml as enableOCSP='false' to enableOCSP='true'
            2.3 Remove ocspResponderUrl and ocspResponderNickname parameter
        3. Start the KRA instance
        4. Tail on CA's debug log
    :ExpectedResults:
        1. CA's internal OCSP responder will come to live and log will show KRA subsystem cert's
           which has AIA extension.

    """
    # Stop the KRA
    ansible_module.command('systemctl stop pki-tomcatd@{}.service'.format(
        constants.KRA_INSTANCE_NAME))
    # Modify the changes
    server_path = '/var/lib/pki/{}/conf/server.xml'.format(constants.KRA_INSTANCE_NAME)

    ansible_module.shell('cp {} {}'.format(server_path, kra_server_xml))
    ansible_module.replace(dest=server_path, regexp='enableOCSP="false"',
                           replace='enableOCSP="true"')
    ocspResponderUrl_regex = 's/ocspResponderURL=\"http:\/\/pki1.example.com:{}\/ca\/ocsp\"//g'. \
        format(constants.KRA_HTTP_PORT)
    ocspResponderNick_regex = 's/ocspResponderCertNickname="ocspSigningCert cert-pki-ca"//g'
    ansible_module.command("sed -i '{}' {}".format(ocspResponderUrl_regex, server_path))
    ansible_module.command("sed -i '{}' {}".format(ocspResponderNick_regex, server_path))
    internal_pass_file = '/tmp/internal_pass.txt'
    instance_db = '/var/lib/pki/{}/alias'.format(constants.KRA_INSTANCE_NAME)
    grep_internal_password = "grep 'internal=' /var/lib/pki/{}/conf/password.conf | cut -d'=' -f2 > {}".format(
        constants.KRA_INSTANCE_NAME, internal_pass_file)
    ansible_module.shell(grep_internal_password)

    # Find KRA subsystem's cert name
    cert_names = []
    find_kra_certs = 'pki -d {} -C {} client-cert-find'.format(instance_db, internal_pass_file)
    find_certs = ansible_module.shell(find_kra_certs)
    for result in find_certs.values():
        if result['rc'] == 0:
            nick_list = re.findall("Nickname:.*", result['stdout'])
            for i in nick_list:
                cert_names.append(i.split(":")[1].strip())
        else:
            log.error("Failed to find the certificate nicks")
            log.error("Failed to run: {}".format(result['cmd']))
            log.error(result['stdout'])
            log.error(result['stderr'])
            pytest.fail()

    # Find KRA subsystem's cert serial from nickname except auditSigningCert
    cert_serial = []
    for nick in cert_names:
        if not nick.startswith('auditSigningCert') and not nick.startswith('CA Signing Certificate'):
            find_kra_serial = 'pki -d {} -C {} client-cert-show "{}"'.format(instance_db,
                                                                             internal_pass_file, nick)
            find_serials = ansible_module.shell(find_kra_serial)
            for result in find_serials.values():
                if result['rc'] == 0:
                    serial_list = re.findall("Serial Number: [\w].*", result['stdout'])
                    for i in serial_list:
                        cert_serial.append(i.split(":")[1].strip())
                else:
                    log.error("Failed to find the certificate serials")
                    log.error("Failed to run: {}".format(result['cmd']))
                    log.error(result['stdout'])
                    log.error(result['stderr'])
                    pytest.fail()

    # Start the KRA
    ansible_module.command('systemctl start pki-tomcatd@{}.service'.format(constants.KRA_INSTANCE_NAME))
    time.sleep(20)

    # Grep the cert serials from debug log of CA
    date = datetime.datetime.now().strftime("%Y-%m-%d")
    debug_path = "/var/log/pki/{}/ca/debug.{}.log".format(constants.CA_INSTANCE_NAME, date)
    cert_serial_find_output = ansible_module.command('tail -n 1000 {}'.format(debug_path))
    for result in cert_serial_find_output.values():
        if result['rc'] == 0:
            raw_serial = re.findall("Serial Number: [\w].*", result['stdout'])
            for no in cert_serial:
                assert 'Serial Number: {}'.format(int(str(no), 16)) in raw_serial
                log.info("Found serial no: {}".format(no))
        else:
            log.error("Failed to grep : {}".format(result['cmd']))
    ansible_module.command('mv -f {} {}'.format(kra_server_xml, server_path))


def test_remove_topo00_setup_of_ldap_ca_and_kra(ansible_module):
    """
        :Title: Remove topology-00 setup of ldap, ca & kra
        :Description: remove setup ldap, ca & kra
        :Requirement:
        :CaseComponent:
        :Setup: Use the subsystems setup in ansible to run subsystem commands
        :Steps:
            1. Destroy KRA instance
            2. Destroy CA instance
            3. Remove LDAP server
        :Expected Results:
            1. It should remove all the instance for topo00_setup.
    """
    # Remove KRA instance
    remove_kra = ansible_module.shell('pkidestroy -s KRA -i {}'.format(constants.KRA_INSTANCE_NAME))
    for result in remove_kra.values():
        assert result['rc'] == 0
        log.info("KRA removed successfully")
        time.sleep(5)

    # Remove CA instance
    remove_ca = ansible_module.shell('pkidestroy -s CA -i {}'.format(constants.CA_INSTANCE_NAME))
    for result in remove_ca.values():
        assert result['rc'] == 0
        log.info("CA removed successfully.")
        time.sleep(5)

    # Remove Ldap server
    remove_ldap = ansible_module.shell('dsctl topology-00-testingmaster remove --do-it')
    for result in remove_ldap.values():
        assert result['rc'] == 0
        log.info("LDAP removed successfully.")
    ansible_module.shell('rm -rf /tmp/test_conf/')
