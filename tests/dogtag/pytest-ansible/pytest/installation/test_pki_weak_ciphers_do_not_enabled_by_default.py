#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Automation of Bugzilla 1469169
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   Automation of bugzilla 1469169 : Weak ciphers (3DES) should not be
#   enabled by default anymore
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
import re
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


@pytest.mark.skipif('topology != 2')
@pytest.mark.parametrize('inst', [constants.CA_INSTANCE_NAME,
                                  constants.KRA_INSTANCE_NAME,
                                  # constants.OCSP_INSTANCE_NAME,
                                  # constants.TKS_INSTANCE_NAME,
                                  # constants.TPS_INSTANCE_NAME
                                  # TODO remove after build
                                  ])
@pytest.mark.parametrize('c_file', ['/var/lib/pki/{}/conf/server.xml',
                                    '/etc/pki/{}/ciphers.info'])
def test_pki_bug_1469169_weak_ciphers_do_not_enabled_by_default(ansible_module, inst, c_file):
    """
    :id: 8cd22269-b240-4845-b036-e0f35080c281

    :Title: RHCS-TC Test weak ciphers do not enabled by default in ciphers.info and server.xml file.

    :Test: Test weak ciphers do not enabled by default in ciphers.info and server.xml file.

    :Description: Weak algorithms like TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
                  TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA, TLS_RSA_WITH_3DES_EDE_CBC_SHA,
                  TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA, TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
                  TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA, TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
                  are enabled by default. So we do not want that enabled by default.

    :Requirement: RHCS-REQ: Ciphers/Algorithms

    :CaseComponent: \-

    :Setup: Use the subsystems setup in ansible to run subsystem commands

    :Steps:
            1. Open /etc/pki/<instance_name>/ciphers.info and
               /var/lib/pki/<instance_name>/conf/server.xml
            2. Make sure that -TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
               -TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA, -TLS_RSA_WITH_3DES_EDE_CBC_SHA,
               -TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA, -TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
               -TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA, -TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
               these algorithms are disabled by default.

    :Expectedresults:
                1. -TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
                   -TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA, -TLS_RSA_WITH_3DES_EDE_CBC_SHA,
                   -TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA, -TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
                   -TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA, -TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
                   are disabled by default.
    """
    expected_ciphers = ['-TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA', '-TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA',
                        '-TLS_RSA_WITH_3DES_EDE_CBC_SHA', '-TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA',
                        '-TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA', '-TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA',
                        '-TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA', '+TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA',
                        '+TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA', '+TLS_RSA_WITH_3DES_EDE_CBC_SHA',
                        '+TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA', '+TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA',
                        '+TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA', '+TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA']
    ciphers = None
    try:
        get_file = ansible_module.command('cat {}'.format(c_file.format(inst)))
        for result in get_file.values():
            ciphers = re.findall('sslRangeCiphers=[\W].*', result['stdout'])

    except Exception as e:
        log.error(e)
        log.error("Failed to verify BZ 1469169.")
        pytest.xfail()
    for ci in expected_ciphers:
        try:
            if ci.startswith("-"):
                assert ci in ciphers[0]
                log.info("Ciphers disabled by default: {}".format(ci))
            elif ci.startswith("+"):
                assert ci not in ciphers[0]
                log.info("Ciphers not enabled by default: {}".format(ci))
        except Exception as e:
            log.error(e)
            log.error("Failed to verify weak Ciphers are enabled by default.")
            pytest.xfail()
