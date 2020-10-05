#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Renaming stream branches in PKI 10.6 modules
#                for RHEL 8.1
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Amol Kahat <akahat@redhat.com>
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
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""
import logging
import os
import random
import re
import sys
import tempfile

import pytest

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

TOPOLOGY = int(constants.CA_INSTANCE_NAME.split("-")[-2])
log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)


@pytest.fixture()
def setup_fixture(ansible_module):
    ansible_module.command('cp -r /tmp/test_dir/ /tmp/test_conf/')

    log.info("Creating ldap instance.")
    ldap_setup = ansible_module.command('dscreate from-file /tmp/test_conf/ldap.cfg')
    for r in ldap_setup.values():
        assert r['rc'] == 0
        log.info("Created ldap instance.")

    log.info("Creating CA instance.")
    ca_setup = ansible_module.command('pkispawn -s CA -f /tmp/test_conf/ca.cfg')
    for r in ca_setup.values():
        assert r['rc'] == 0
        log.info("Created CA instance.")
    ansible_module.copy(src='/var/lib/pki/{}/alias/ca.crt'.format(constants.CA_INSTANCE_NAME), dest='/tmp/rootCA.pem', remote_src='yes' )
    log.info("Creating KRA instance.")
    kra_setup = ansible_module.command('pkispawn -s KRA -f /tmp/test_conf/kra.cfg')
    for r in kra_setup.values():
        assert r['rc'] == 0
        log.info("Created KRA instance.")

    yield

    # teardown
    log.info("Removing KRA instance.")
    res = ansible_module.command('pkidestroy -s KRA -i {}'.format(constants.KRA_INSTANCE_NAME))
    for r in res.values():
        assert r['rc'] == 0
        log.info("Removed KRA instance.")

    log.info("Removing CA instance.")
    res = ansible_module.command('pkidestroy -s CA -i {}'.format(constants.CA_INSTANCE_NAME))
    for r in res.values():
        assert r['rc'] == 0
        log.info("Removed CA instance.")

    log.info("Removing ldap instance.")
    instance_name = "-".join(constants.CA_INSTANCE_NAME.split("-")[:-1])
    res = ansible_module.command('dsctl slapd-{}-testingmaster remove --do-it'.format(instance_name))
    for r in res.values():
        assert r['rc'] == 0
        log.info("Removed ldap instance.")


@pytest.mark.skipif("TOPOLOGY != 0")
def test_pki_bug_1579614_and_1641874(ansible_module, setup_fixture):
    """
    :Title: Test pki bug 1769614 insecure defaults in cors filter enable and openredirect
    :Description: Test pki bug 1769614 insecure defaults in cors filter enable and openredirect
    :Requirement:
    :CaseComponent: \-
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. Install CA, Install KRA
        2. Perform Key archival
    :ExpectedResults:
        1. Key archival should be successful.
    """
    temp_dir = tempfile.mkdtemp(suffix="_pki", prefix="test_")

    # setup

    t = ansible_module.command('pki -d {} -c {} client-init '
                               '--force'.format(temp_dir, constants.CLIENT_DATABASE_PASSWORD))
    log.info("Initialize client dir: {}".format(temp_dir))
    command = 'pki -d {} -c {} -p {} client-cert-import --ca-server RootCA'.format(temp_dir,
                                                                                   constants.CLIENT_DATABASE_PASSWORD,
                                                                                   constants.CA_HTTPS_PORT)
    t = ansible_module.expect(command=command,responses={"Trust this certificate (y/N)?": "y"})

    log.info("Imported RootCA cert.")
    t = ansible_module.command('pki -d {} -c {} client-cert-import --pkcs12 {} '
                               '--pkcs12-password {}'.format(temp_dir, constants.CLIENT_DATABASE_PASSWORD,
                                                             constants.CA_CLIENT_DIR + "/ca_admin_cert.p12",
                                                             constants.CLIENT_PKCS12_PASSWORD))
    log.info("Imported CA Admin Cert.")
    t = ansible_module.command('pki -d {} -c {} client-cert-import --pkcs12 {} '
                               '--pkcs12-password {}'.format(temp_dir, constants.CLIENT_DATABASE_PASSWORD,
                                                             constants.KRA_CLIENT_DIR + "/kra_admin_cert.p12",
                                                             constants.CLIENT_PKCS12_PASSWORD))
    log.info("Imported KRA Admin Cert.")

    user = "testuser{}".format(random.randint(99, 9999))
    subject = "UID={},CN={}".format(user, user)
    transport_file = '/tmp/transport.pem'

    get_transport = ansible_module.pki(cli='ca-cert-find',
                                       nssdb=temp_dir,
                                       dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                       port=constants.CA_HTTP_PORT,
                                       certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                       extra_args='--name "DRM Transport Certificate"')

    for r in get_transport.values():
        if r['rc'] == 0:
            get_no = re.findall("Serial Number.*", r['stdout'])
            transport_no = get_no[0].split(":")[1].strip()
            log.info("Got transport serial: {}".format(transport_no))

            get_cert = ansible_module.pki(cli='ca-cert-show',
                                          nssdb=temp_dir,
                                          dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                          port=constants.CA_HTTP_PORT,
                                          certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                          extra_args='{} --output {}'.format(transport_no,
                                                                             transport_file))
            for r1 in get_cert.values():
                assert r1['rc'] == 0
                log.info("Got transport cert: {}".format(transport_file))

    key_archive = ansible_module.pki(cli='client-cert-request',
                                     nssdb=temp_dir,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                     extra_args='"{}" --type crmf --transport {}'.format(subject, transport_file))
    for r in key_archive.values():
        assert r['rc'] == 0
        get_req_no = re.findall('Request ID:.*', r['stdout'])
        req_no = get_req_no[0].split(":")[1].strip()
        log.info("Created certificate request: {}".format(req_no))

    approve_req = ansible_module.pki(cli='ca-cert-request-review',
                                     nssdb=temp_dir,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     port=constants.CA_HTTP_PORT,
                                     certnick="'{}'".format(constants.CA_ADMIN_NICK),
                                     extra_args='{} --action approve'.format(req_no))
    for r in approve_req.values():
        assert r['rc'] == 0
        get_serial_no = re.findall("Certificate ID:.*", r['stdout'])
        serial_no = get_serial_no[0].split(":")[1].strip()
        log.info("Certificate request approved: {}".format(serial_no))

    command = 'pki -d {} -c {} -p {} -n "{}" kra-key-find'.format(temp_dir,
                                                                  constants.CLIENT_DATABASE_PASSWORD,
                                                                  constants.KRA_HTTPS_PORT, constants.KRA_ADMIN_NICK)
    find_key = ansible_module.expect(command=command,responses={"Trust this certificate (y/N)?": "y"})

    for r in find_key.values():
        assert r['rc'] == 0
        assert "Owner: {}".format(subject) in r['stdout']
        log.info("Key archived successfully.")
