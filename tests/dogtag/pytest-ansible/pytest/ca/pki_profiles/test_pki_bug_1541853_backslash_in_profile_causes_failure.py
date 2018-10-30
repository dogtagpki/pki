#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Automation of BZ: 1541853 Backslash in Profile
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   Backslash in profile causes failure in certificate issuance
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Amol Kahat <akahat@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2017 Red Hat, Inc. All rights reserved.
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

from pki.testlib.common.utils import UserOperations, ProfileOperations

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

userop = UserOperations(nssdb=constants.NSSDB)
profop = ProfileOperations(nssdb=constants.NSSDB)

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)


def test_bug_1541853_backslash_in_profile_failure_in_cert_issuance(ansible_module):
    """
    :id: e6f0874e-30f2-4510-b8ff-a1f659e82fcb

    :Title: Test bug 1541853: Backslash in profile causes certificate issuance failure.

    :Test: Test bug 1541853: Backslsh in profile causes certificate issuance failure.

    :Description: When writing (importing, updating) RAW profile data, config values that have
                  backslashes in them have the backslashes dropped, leading issuance failure or
                  issuance of correct certificate.

                  For Ex:
                    policyset.serverCertSet.1.default.params.name=CN=$request.req_subject_name.cn$,
                    O=Red Hat\, Inc.

    :Requirement: RHCS-REQ Certificate Authority Profiles

    :CaseComponent: \-

    :Setup: Use the subsystems setup in ansible to run subsystem commands

    :Steps:
            1. Get profile caServerCert in raw format.
            2. Change the id of the profile. Modify the attribute `default.params.name` to
               CN\=$request.request_subject_name.cn$,O\=Red Hat\, Inc.
            3. Add profile to CA and enable it.
            4. Show the profile in raw format. Make sure that `default.params.name` attribute
            value does not contain the backslash.
            5. Issue the certificate using the profile

    :Expectedresults:
                1. Certificate issuance should be successful.
                2. Make sure that backslashes are not present in the raw profile.
    """
    file_name = '/tmp/caServerCert.txt'
    profile = 'caServerCert'
    replace_param = 'policyset.serverCertSet.1.default.params.name=.*'
    param_string = 'policyset.serverCertSet.1.default.params.name=' \
                   'CN\=$request.request_subject_name.cn$,O\=Red Hat\, Inc.'

    profile_show = ansible_module.pki(cli='ca-profile-show',
                                      nssdb=constants.NSSDB,
                                      port=constants.CA_HTTP_PORT,
                                      dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                      certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                      extra_args='{} --raw --output {}'.format(profile, file_name))

    for result in profile_show.values():
        if result['rc'] == 0:
            log.info("Changing {} to {}.".format(replace_param, param_string))
            ansible_module.lineinfile(dest=file_name, regexp=replace_param, line=param_string)
        else:
            log.error("Failed to get caServerCert profile.")
            log.error("Failed to run: {}".format(result['cmd']))
            pytest.xfail()
    disabled = profop.disable_profile(ansible_module, profile)
    assert disabled

    update_prof = ansible_module.pki(cli='ca-profile-mod',
                                     nssdb=constants.NSSDB,
                                     port=constants.CA_HTTP_PORT,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='{} --raw'.format(file_name))

    for result in update_prof.values():
        if result['rc'] == 0:
            log.info("Changed profile.")
        else:
            log.error("Failed to update the profile.")
            pytest.xfail("Failed to update profile.")
    enabled = profop.enable_profile(ansible_module, profile_name=profile)
    assert enabled

    ca_ser_cert = ansible_module.pki(cli='ca-profile-show',
                                     nssdb=constants.NSSDB,
                                     port=constants.CA_HTTP_PORT,
                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                     extra_args='caServerCert --raw')
    for res in ca_ser_cert.values():
        if res['rc'] == 0:
            assert param_string in res['stdout']
        else:
            pytest.xfail("Failed to run caServerCert profile.")

    subject = 'CN=pki1.example.com'
    cert_id = userop.process_certificate_request(ansible_module, subject=subject, profile=profile,
                                                 keysize=2048)

    cert_show_out = ansible_module.pki(cli='ca-cert-show',
                                       nssdb=constants.NSSDB,
                                       port=constants.CA_HTTP_PORT,
                                       dbpassword=constants.CLIENT_DATABASE_PASSWORD,
                                       certnick='"{}"'.format(constants.CA_ADMIN_NICK),
                                       extra_args='{}'.format(cert_id))

    for res in cert_show_out.values():
        if res['rc'] == 0:
            assert '\\' not in res['stdout']
            log.info(res['stdout'])
        else:
            pytest.xfail()
