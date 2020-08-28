#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: ExternalCA Supporting functions
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   This is the library for ExternalCA sypporting class and Functions.
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Geetika Kapoor <gkapoor@redhat.com>
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
import sys

import pytest

from utils import *

if os.path.isfile('/tmp/test_dir/constants.py'):
    import sys
    sys.path.append('/tmp/test_dir')
    import constants

setup = pytest.mark.setup
teardown = pytest.mark.teardown

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)

@setup
@pytest.yield_fixture()
def config_setup(request,ansible_module):
    '''
    This fixture is going to setup configuration files.This is done by passing
    params in  dictionary format.
    '''
    instance_creation = openssl_externalca()
    config = Config()

    params_default = {"pki_hostname": map(str,[ansible_module.shell('hostname')[x]['stdout']
                                               for x in ansible_module.shell('hostname').iterkeys()])[0],
                      "pki_ds_password":instance_creation.passwd,"pki_ds_ldap_port": constants.LDAP_PORT}

    subsystem_params_step1 = {"pki_admin_email":"caadmin1@example.com","pki_admin_name":"caadmin",
                              "pki_admin_nickname":constants.CA_ADMIN_USERNAME,"pki_admin_password":instance_creation.passwd,
                              "pki_admin_uid": constants.CA_ADMIN_USERNAME,"pki_backup_keys":"True",
                              "pki_backup_password":instance_creation.passwd,
                              "pki_client_database_password":instance_creation.passwd,
                              "pki_client_database_purge":"False","pki_ds_base_dn":"dc=ca,dc=example,dc=com",
                              "pki_client_pkcs12_password":instance_creation.passwd,"pki_ds_database":"ca",
                              "pki_ds_password":instance_creation.passwd,"pki_security_domain_name":"EXAMPLE",
                              "pki_token_password":instance_creation.passwd,"pki_external":"True",
                              "pki_external_step_two":"False", "pki_ca_signing_csr_path":instance_creation.ca_signing_csr
                              }

    subsystem_params_step2 = {"pki_cert_chain_path":instance_creation.rootca_signing_crt,
                              "pki_ca_signing_cert_path":instance_creation.ca_signing_crt
                              }
    
    subsystem_params_step2.update(subsystem_params_step1)
    subsystem_params_step2["pki_external_step_two"]="True"

    if os.path.isfile("{}".format(instance_creation.config_step2)) and \
            os.path.isfile("{}".format(instance_creation.config_step1)):
        log.info("Configuration file exist")
        yield("resource")
        log.info("teardown before exit")
        for x in ['rm -rf %s %s' %(instance_creation.nssdb, instance_creation.pass_file),
                  'pkidestroy -s %s -i %s' % (instance_creation.subsystem, instance_creation.instance_name)]:
            ansible_module.shell(x)
            log.info("Teardown: Remove %s",x)

    else:
        log.info("Create the configuration files")
        config.add_default(instance_creation.config_step1, **params_default)
        config.add_section(instance_creation.config_step1, 'CA', **subsystem_params_step1)
        ansible_module.copy(src=instance_creation.config_step1, dest=instance_creation.config_step1)

        config.add_default(instance_creation.config_step2, **params_default)
        config.add_section(instance_creation.config_step2, 'CA', **subsystem_params_step2)
        ansible_module.copy(src=instance_creation.config_step2, dest=instance_creation.config_step2)
        yield("resource")
        log.info("teardown before exit")
        for x in ['rm -rf %s %s' %(instance_creation.nssdb, instance_creation.pass_file),
                  'pkidestroy -s %s -i %s' % (instance_creation.subsystem, instance_creation.instance_name)]:
            ansible_module.shell(x)
            log.info("Teardown: Remove %s",x)
